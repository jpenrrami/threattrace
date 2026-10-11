# ThreatTrace

ThreatTrace is a defensive malware-analysis pipeline. It ingests authorized
sample metadata, coordinates CAPE analysis, stores normalized evidence in
PostgreSQL, and produces detection exports and Velociraptor artifacts for
isolated endpoint validation.

This repository contains source code and declarative configuration only. It
does not include malware, credentials, analysis reports, runtime storage, or
endpoint-collection outputs.

## Architecture

```text
Configured sources -> PostgreSQL -> CAPE -> normalized evidence
                                      -> detection exports / Velociraptor artifacts
```

ThreatTrace connects to user-provided PostgreSQL, Redis, CAPE, Velociraptor,
MalwareBazaar, and MalShare services. It does not install or configure them.

## Safety

Use ThreatTrace only in systems you own or are authorized to test. Keep CAPE,
staging services, and Windows validation guests isolated from production.
Review every generated artifact before deployment. Commands that can execute a
sample require explicit execution and confirmation flags.

## Requirements

- Python 3.13 to 3.14
- PostgreSQL
- Redis for Celery workers
- CAPE for sandbox workflows
- Velociraptor, libvirt/KVM, and optionally WinRM for endpoint validation

## Install

```bash
git clone <repository-url> threattrace
cd threattrace
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[all]'
cp .env.example .env
chmod 600 .env
```

Set the lab-specific values in `.env`. Do not commit that file.

Initialize an empty configured database:

```bash
threattrace db init --dry-run
threattrace db init
```

`db init` creates an empty schema or verifies an exact compatible schema. It
does not migrate an existing incompatible database.

## CLI

```bash
threattrace --help
threattrace db --help
threattrace ingest --help
threattrace cape --help
threattrace detection --help
threattrace vr --help
```

Primary command groups:

- `db`: initialize and harden the PostgreSQL schema.
- `ingest`: acquire and register sample metadata from configured sources.
- `cape`: submit, poll, archive, recover, and enrich sandbox analyses.
- `detection`: export detection data and generate reviewable artifacts.
- `vr`: prepare, run, collect, compare, and clean isolated endpoint-validation workflows.

Start with the relevant `--help` output and `--dry-run` where available.

## Basic flow

1. Configure external services in `.env`.
2. Initialize the database.
3. Ingest authorized sample metadata.
4. Run CAPE work only in an isolated environment.
5. Review exported detections and endpoint artifacts before use.

## Configuration

`.env.example` documents the environment variables used by the package. It
contains placeholders only. Runtime defaults and declarative rules live under
`config/` and are installed with the wheel.

For network-hardening commands, set all `THREATTRACE_VR_*` network values in
the environment; the published configuration deliberately contains no lab
topology.

## Package checks

```bash
make check
```

The check runs Ruff, compiles the package, builds a wheel, and is designed for
the publishable source tree.
