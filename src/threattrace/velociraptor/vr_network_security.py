from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.redaction import redact_secrets
from threattrace.velociraptor.vr_config import load_vr_config
from threattrace.velociraptor.vr_winrm import run_powershell

CONFIG_PATH = config_path("velociraptor", "network_rules.json")


def _network_rules() -> dict[str, Any]:
    return load_json_config(str(CONFIG_PATH))


_CFG = load_vr_config()
_RULES = _network_rules()
HOST_IP = os.environ.get("THREATTRACE_VR_STAGING_BIND_HOST", _CFG.staging_bind_host)
VALIDATION_NET = os.environ.get("THREATTRACE_VR_VALIDATION_NET", str(_RULES["validation_net"]))
VALIDATION_BRIDGE = os.environ.get("THREATTRACE_VR_VALIDATION_BRIDGE", str(_RULES["validation_bridge"]))
INETSIM_IP = os.environ.get("THREATTRACE_VR_INETSIM_IP", HOST_IP or str(_RULES["inetsim_ip"]))
VELOCIRAPTOR_FRONTEND_IP = os.environ.get("THREATTRACE_VR_FRONTEND_IP", HOST_IP or str(_RULES["velociraptor_frontend_ip"]))
LIBVIRT_NETWORK_NAME = str(_RULES["libvirt_network_name"])
VELOCIRAPTOR_FRONTEND_PORT = int(_RULES["velociraptor_frontend_port"])
VELOCIRAPTOR_GUI_PORT = int(_RULES["velociraptor_gui_port"])
GUEST_TEST_TIMEOUT_MS = int(_RULES["guest_test_timeout_ms"])
STAGING_PORT_MIN = int(_RULES["staging_port_min"])
STAGING_PORT_MAX = int(_RULES["staging_port_max"])
NFT_TABLE = str(_RULES["nft_table"])
BRIDGE_TABLE = str(_RULES["bridge_table"])
BACKUP_DIR = Path(os.environ.get("THREATTRACE_VR_NETWORK_BACKUP_DIR", str(_RULES["network_backup_dir"])))

FAKE_TCP_PORTS = str(_RULES["fake_tcp_ports"])
FAKE_UDP_PORTS = str(_RULES["fake_udp_ports"])


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    def as_dict(self) -> dict[str, Any]:
        return redact_secrets({
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[:12000],
            "stderr": self.stderr[:4000],
        })


def _now_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")


def _run(command: list[str], check: bool = False) -> CommandResult:
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr)
    if check and completed.returncode != 0:
        raise SystemExit(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return result


def _print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _root_required() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Run as root. Example: sudo threattrace vr network harden")


def _require_execute(args: argparse.Namespace, confirm_attr: str | None = None) -> None:
    if not getattr(args, "execute", False):
        raise SystemExit("--execute required for guest network actions")
    if confirm_attr and not getattr(args, confirm_attr, False):
        raise SystemExit(f"--execute requires --{confirm_attr.replace('_', '-')}")


def _require_network_settings() -> None:
    missing = [
        name
        for name, value in {
            "THREATTRACE_VR_STAGING_BIND_HOST": HOST_IP,
            "THREATTRACE_VR_VALIDATION_NET": VALIDATION_NET,
            "THREATTRACE_VR_VALIDATION_BRIDGE": VALIDATION_BRIDGE,
            "THREATTRACE_VR_INETSIM_IP": INETSIM_IP,
            "THREATTRACE_VR_FRONTEND_IP": VELOCIRAPTOR_FRONTEND_IP,
        }.items()
        if not value
    ]
    if missing:
        raise SystemExit(f"Set isolated-lab network settings: {', '.join(missing)}")
    try:
        ipaddress.ip_network(VALIDATION_NET, strict=False)
        for value in (HOST_IP, INETSIM_IP, VELOCIRAPTOR_FRONTEND_IP):
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise SystemExit(f"Invalid isolated-lab network setting: {exc}") from exc


def _socket_check(host: str, port: int, timeout: float = 3.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def _virsh(cfg, *args: str) -> list[str]:
    return ["virsh", "-c", cfg.libvirt_uri, *args]


def _vm_tap_interfaces(*, cfg=None) -> list[str]:
    cfg = cfg or load_vr_config()
    interfaces: list[str] = []
    for vm_name in cfg.vms:
        result = _run(_virsh(cfg, "domiflist", vm_name))
        for line in result.stdout.splitlines():
            columns = line.split()
            if len(columns) >= 3 and columns[2] == LIBVIRT_NETWORK_NAME and columns[0].startswith("vnet"):
                interfaces.append(columns[0])
    return sorted(set(interfaces))


def _nft_rules(vm_taps: list[str]) -> str:
    bridge_rule = ""
    if len(vm_taps) >= 2:
        quoted_taps = ", ".join(f'"{item}"' for item in vm_taps)
        bridge_rule = f"""
table bridge {BRIDGE_TABLE} {{
  chain forward {{
    type filter hook forward priority -20; policy accept;
    iifname {{ {quoted_taps} }} oifname {{ {quoted_taps} }} drop comment "threattrace-vr deny VM-to-VM at bridge"
  }}
}}
"""
    return f"""table inet {NFT_TABLE} {{
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ct state established,related accept comment "threattrace-vr allow established VM replies"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {HOST_IP} udp dport 67 accept comment "threattrace-vr allow DHCP renew"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {HOST_IP} tcp dport 53 accept comment "threattrace-vr allow DNS TCP"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {HOST_IP} udp dport 53 accept comment "threattrace-vr allow DNS UDP"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {HOST_IP} tcp dport {STAGING_PORT_MIN}-{STAGING_PORT_MAX} accept comment "threattrace-vr allow temporary HTTP staging"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {VELOCIRAPTOR_FRONTEND_IP} tcp dport {VELOCIRAPTOR_FRONTEND_PORT} accept comment "threattrace-vr allow Velociraptor frontend"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {INETSIM_IP} tcp dport {{ {FAKE_TCP_PORTS} }} accept comment "threattrace-vr allow INetSim TCP"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ip daddr {INETSIM_IP} udp dport {{ {FAKE_UDP_PORTS} }} accept comment "threattrace-vr allow INetSim UDP"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} reject comment "threattrace-vr deny VM access to host/server services"
  }}

  chain forward {{
    type filter hook forward priority -20; policy accept;
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} ct state established,related accept comment "threattrace-vr allow established forwarded replies"
    iifname "{VALIDATION_BRIDGE}" oifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} reject comment "threattrace-vr deny VM-to-VM"
    iifname "{VALIDATION_BRIDGE}" ip saddr {VALIDATION_NET} reject comment "threattrace-vr deny VM routed egress"
  }}
}}
{bridge_rule}"""


def audit(_args: argparse.Namespace) -> None:
    _require_network_settings()
    cfg = load_vr_config()
    vm_names = sorted(cfg.vms)
    commands = {
        "ip_addr": ["ip", "-br", "addr"],
        "ip_route": ["ip", "route"],
        "ip_forward": ["sysctl", "net.ipv4.ip_forward"],
        "libvirt_net_info": _virsh(cfg, "net-info", LIBVIRT_NETWORK_NAME),
        "libvirt_net_xml": _virsh(cfg, "net-dumpxml", LIBVIRT_NETWORK_NAME),
        **{f"{name}_if": _virsh(cfg, "domiflist", name) for name in vm_names},
        "listeners": ["ss", "-lntup"],
        "inetsim": ["systemctl", "status", "inetsim", "--no-pager"],
        "nft_threattrace": ["nft", "list", "table", "inet", NFT_TABLE],
        "nft_bridge": ["nft", "list", "table", "bridge", BRIDGE_TABLE],
        "nft_ruleset": ["nft", "list", "ruleset"],
    }
    payload: dict[str, Any] = {
        "model": {
            "validation_net": VALIDATION_NET,
            "bridge": VALIDATION_BRIDGE,
            "host_ip": HOST_IP,
            "staging_ports": f"{STAGING_PORT_MIN}-{STAGING_PORT_MAX}",
            "velociraptor_frontend": f"{VELOCIRAPTOR_FRONTEND_IP}:{VELOCIRAPTOR_FRONTEND_PORT}",
            "velociraptor_gui_denied": f"{VELOCIRAPTOR_FRONTEND_IP}:{VELOCIRAPTOR_GUI_PORT}",
            "inetsim": INETSIM_IP,
            "vms": {name: {"host": vm.host, "winrm_port": vm.winrm_port} for name, vm in cfg.vms.items()},
            "vm_tap_interfaces": _vm_tap_interfaces(cfg=cfg),
        },
        "frontend_reachable_from_host": _socket_check(VELOCIRAPTOR_FRONTEND_IP, VELOCIRAPTOR_FRONTEND_PORT),
        "commands": {name: _run(command).as_dict() for name, command in commands.items()},
    }
    _print(payload)


def harden(_args: argparse.Namespace) -> None:
    _require_network_settings()
    _root_required()
    cfg = load_vr_config()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = BACKUP_DIR / f"nft-ruleset-before-{_now_slug()}.nft"
    backup.write_text(_run(["nft", "list", "ruleset"], check=True).stdout, encoding="utf-8")
    vm_taps = _vm_tap_interfaces(cfg=cfg)
    rules = _nft_rules(vm_taps)
    _run(["nft", "delete", "table", "inet", NFT_TABLE])
    _run(["nft", "delete", "table", "bridge", BRIDGE_TABLE])
    completed = subprocess.run(["nft", "-f", "-"], input=rules, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.stderr)
    _print({"applied": True, "tables": [f"inet {NFT_TABLE}", f"bridge {BRIDGE_TABLE}"], "vm_tap_interfaces": vm_taps, "backup": str(backup)})


def rollback(_args: argparse.Namespace) -> None:
    if getattr(_args, "dry_run", False):
        _print({
            "dry_run": True,
            "commands": [
                ["nft", "delete", "table", "inet", NFT_TABLE],
                ["nft", "delete", "table", "bridge", BRIDGE_TABLE],
            ],
        })
        return
    _root_required()
    inet_result = _run(["nft", "delete", "table", "inet", NFT_TABLE])
    bridge_result = _run(["nft", "delete", "table", "bridge", BRIDGE_TABLE])
    _print({
        "removed_tables": [f"inet {NFT_TABLE}", f"bridge {BRIDGE_TABLE}"],
        "inet_returncode": inet_result.returncode,
        "bridge_returncode": bridge_result.returncode,
        "stderr": f"{inet_result.stderr}{bridge_result.stderr}",
    })


def _vm_test_script(host_ip: str, inetsim_ip: str, other_vm_ip: str, staging_port: int) -> str:
    return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
function Test-TcpPort($HostName, $Port, $TimeoutMs = {GUEST_TEST_TIMEOUT_MS}) {{
  try {{
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect($HostName, [int]$Port, $null, $null)
    $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
    if ($ok -and $client.Connected) {{
      $client.EndConnect($async)
      $client.Close()
      return $true
    }}
    $client.Close()
    return $false
  }} catch {{
    return $false
  }}
}}
$tests = @(
  @{{name='velociraptor_frontend_{VELOCIRAPTOR_FRONTEND_PORT}'; host='{VELOCIRAPTOR_FRONTEND_IP}'; port={VELOCIRAPTOR_FRONTEND_PORT}; expect=$true}},
  @{{name='velociraptor_gui_{VELOCIRAPTOR_GUI_PORT}'; host='{VELOCIRAPTOR_FRONTEND_IP}'; port={VELOCIRAPTOR_GUI_PORT}; expect=$false}},
  @{{name='host_staging_{staging_port}'; host='{host_ip}'; port={staging_port}; expect=$null}},
  @{{name='host_ssh_22'; host='{host_ip}'; port=22; expect=$false}},
  @{{name='host_postgresql_5432'; host='{host_ip}'; port=5432; expect=$false}},
  @{{name='host_redis_6379'; host='{host_ip}'; port=6379; expect=$false}},
  @{{name='inetsim_http_80'; host='{inetsim_ip}'; port=80; expect=$true}},
  @{{name='external_https_443'; host='1.1.1.1'; port=443; expect=$false}},
  @{{name='other_vm_winrm_5985'; host='{other_vm_ip}'; port=5985; expect=$false}}
)
$out = foreach ($t in $tests) {{
  $r = Test-TcpPort $t.host $t.port
  [PSCustomObject]@{{name=$t.name; host=$t.host; port=$t.port; reachable=[bool]$r; expect=$t.expect; pass=($t.expect -eq $null -or [bool]$r -eq [bool]$t.expect)}}
}}
$out | ConvertTo-Json -Compress
"""


def configure_inetsim_dns(_args: argparse.Namespace) -> None:
    _require_execute(_args, "confirm_guest_network_change")
    _require_network_settings()
    cfg = load_vr_config()
    script = rf"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$adapters = Get-NetAdapter | Where-Object {{$_.Status -eq 'Up'}} | Select-Object -ExpandProperty InterfaceAlias
foreach ($adapter in $adapters) {{
  Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses {INETSIM_IP}
}}
Get-DnsClientServerAddress -AddressFamily IPv4 | ConvertTo-Json -Compress
"""
    results = {}
    for name, vm in cfg.vms.items():
        results[name] = run_powershell(vm, script, execute=True, timeout_sec=120).as_dict()
    _print(results)


def test_network(args: argparse.Namespace) -> None:
    _require_network_settings()
    cfg = load_vr_config()
    if not STAGING_PORT_MIN <= args.staging_port <= STAGING_PORT_MAX:
        raise SystemExit(f"--staging-port must be within {STAGING_PORT_MIN}-{STAGING_PORT_MAX}")
    by_arch = {vm.arch: vm for vm in cfg.vms.values()}
    x86 = by_arch["x86"]
    x64 = by_arch["x64"]
    host_tests = {
        "host_to_x86_winrm_5985": _socket_check(x86.host, 5985),
        "host_to_x64_winrm_5985": _socket_check(x64.host, 5985),
        f"host_to_velociraptor_frontend_{VELOCIRAPTOR_FRONTEND_PORT}": _socket_check(VELOCIRAPTOR_FRONTEND_IP, VELOCIRAPTOR_FRONTEND_PORT),
    }
    vm_results = {}
    for name, vm in cfg.vms.items():
        other = x64.host if vm.arch == "x86" else x86.host
        script = _vm_test_script(HOST_IP, INETSIM_IP, other, args.staging_port)
        vm_results[name] = run_powershell(vm, script, execute=args.execute, timeout_sec=180).as_dict()
    _print({"host": host_tests, "vms": vm_results})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Velociraptor validation network security")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit").set_defaults(func=audit)
    sub.add_parser("harden").set_defaults(func=harden)
    rollback_parser = sub.add_parser("rollback")
    rollback_parser.add_argument("--dry-run", action="store_true")
    rollback_parser.set_defaults(func=rollback)
    test = sub.add_parser("test")
    test.add_argument("--staging-port", type=int, default=STAGING_PORT_MIN)
    test.add_argument("--execute", action="store_true")
    test.set_defaults(func=test_network)
    dns = sub.add_parser("configure-inetsim-dns")
    dns.add_argument("--execute", action="store_true")
    dns.add_argument("--confirm-guest-network-change", action="store_true")
    dns.set_defaults(func=configure_inetsim_dns)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
