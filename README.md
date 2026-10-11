# ThreatTrace

ThreatTrace is a defensive malware-analysis pipeline for turning authorized sample intelligence and sandbox evidence into reviewable indicator and endpoint-validation outputs. It keeps ingestion, analysis coordination, evidence normalization, detection export, and endpoint validation as separate stages instead of treating a sandbox result as a finished detection.

The project connects metadata sources, CAPE, PostgreSQL, Redis, Celery, and Velociraptor through a Python command-line interface. It is intended for defenders, malware analysts, detection engineers, and lab operators who need a repeatable way to organize analysis evidence before using it in a detection workflow.

ThreatTrace is standalone software. This repository contains source code and declarative configuration only: it does not contain malware, credentials, sandbox reports, runtime storage, or endpoint-collection output.

## Problem It Solves

Malware-analysis workflows commonly split evidence across sample sources, sandbox systems, databases, and endpoint tooling. That separation makes it difficult to trace a candidate indicator back to the evidence that produced it or to determine which results still need analyst review.

ThreatTrace addresses that workflow by:

- ingesting authorized metadata from MalwareBazaar and MalShare;
- coordinating explicitly requested CAPE analysis work;
- normalizing extracted evidence and candidate IoCs into PostgreSQL;
- exporting reviewable detection data and Velociraptor artifact inputs; and
- supporting controlled Velociraptor validation when external infrastructure is available.

It does not perform automatic causal attribution, guarantee complete detection, or turn every observed value into a deployment-ready IoC.

## Architecture

```text
MalwareBazaar / MalShare
 (authorized intelligence and samples)
                 |
                 v
      Ingestion and coordination -----> PostgreSQL
                 |                         ^
                 |                         |
Operator-selected samples --> CAPE --> CAPE reports --> ETL and IoC processing
                                                        |
                                                        v
                                   candidate IoCs and evidence in PostgreSQL
                                                        |
                                                        v
                               detection exports and artifact inputs
                                                        |
                                                        v
                           Velociraptor validation (external, optional)

Redis + Celery (when enabled) --> asynchronous execution of selected work
```

| Component | Role |
| --- | --- |
| MalwareBazaar / MalShare | External sample-intelligence sources used by ingestion commands. |
| Ingestion and coordination | Registers metadata and prepares explicitly requested processing work. |
| CAPE | External malware sandbox used for submitted analysis tasks and reports. |
| ETL and IoC processing | Extracts, normalizes, scores, and organizes observed evidence and candidates. |
| PostgreSQL | Stores pipeline state, evidence, analysis metadata, and exported records. |
| Redis and Celery | Provide the broker and optional asynchronous worker execution. |
| Detection outputs | Exports IoC bundles and generates Velociraptor artifact skeletons. |
| Velociraptor | External endpoint-validation platform used only when configured by the operator. |

Docker Compose includes PostgreSQL, Redis, a CLI container, and an optional Celery worker. CAPE, Velociraptor, virtual machines, KVM/libvirt, WinRM, MalwareBazaar, and MalShare are external dependencies; Compose does not install, start, or configure them.

## Repository Layout

```text
.
├── .github/
│   └── workflows/
│       └── quality.yml
├── config/
│   ├── cape/
│   ├── db/
│   ├── detection/
│   ├── pipeline/
│   └── velociraptor/
├── src/
│   └── threattrace/
│       ├── cape/
│       ├── cli/
│       ├── db/
│       ├── detection/
│       ├── etl/
│       ├── malwarebazaar/
│       ├── malshare/
│       ├── velociraptor/
│       └── workers/
├── .dockerignore
├── .env.example
├── Dockerfile
├── Makefile
├── README.md
├── compose.yaml
├── pyproject.toml
└── requirements.lock
```

## Technologies

### Python dependencies

- **Python 3.13 or 3.14**: supported runtime versions.
- **SQLAlchemy** and **psycopg**: PostgreSQL access and schema management.
- **Celery**: optional background-worker execution.
- **gRPC** and **Protocol Buffers**: Velociraptor API integration support.
- **Requests**: HTTP clients for external integrations.
- **Ruff**: development linting.

### Services and external systems

- **PostgreSQL**: persistent pipeline and evidence storage.
- **Redis**: Celery broker and worker coordination.
- **CAPE**: external sandbox service for malware-analysis workflows.
- **Velociraptor**: external endpoint-validation platform.
- **Docker and Docker Compose**: reproducible local PostgreSQL, Redis, CLI, and worker deployment.

## Requirements

### Docker deployment

- Docker Engine and the Docker Compose plugin.
- Isolated values for the PostgreSQL credentials in `.env`.
- CAPE settings only for CAPE operations.
- Velociraptor, VM, and network settings only for Velociraptor operations.
- Source API settings only when using MalwareBazaar or MalShare ingestion.

Docker Compose starts neither CAPE nor Velociraptor. It also does not mount KVM, libvirt, WinRM, host networking, devices, or the Docker socket.

### Manual installation

- Python 3.13 or 3.14.
- PostgreSQL reachable through `THREATTRACE_DATABASE_URL`.
- Redis reachable through `THREATTRACE_REDIS_URL` when using workers.
- CAPE, Velociraptor, and their supporting infrastructure only for their respective workflows.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/jpenrrami/threattrace.git
cd threattrace
```

### 2. Configure environment variables

```bash
cp .env.example .env
chmod 600 .env
```

For Docker, set `THREATTRACE_POSTGRES_DB`, `THREATTRACE_POSTGRES_USER`, and a URL-safe `THREATTRACE_POSTGRES_PASSWORD`. Compose derives the container database URL and Redis URL from those values.

Use placeholder values for external services until those workflows are needed. For example:

```env
THREATTRACE_POSTGRES_PASSWORD=replace_with_a_long_url_safe_secret
THREATTRACE_CAPE_API_URL=http://cape.example.invalid:8080/apiv2
THREATTRACE_VR_X64_HOST=velociraptor-client.example.invalid
THREATTRACE_MALWAREBAZAAR_API_KEY=
THREATTRACE_MALSHARE_API_KEY=
```

Do not commit `.env`. It is local configuration, not a complete production secret-management solution.

### 3. Build and start Docker services

```bash
docker compose --profile cli build
docker compose up -d --wait
```

The default startup waits for PostgreSQL and Redis healthchecks. It does not ingest metadata, download material, submit CAPE tasks, run endpoint collections, or start a worker.

### 4. Initialize PostgreSQL

```bash
docker compose run --rm threattrace threattrace db init --dry-run
docker compose run --rm threattrace threattrace db init
```

The dry run prints the initialization plan without connecting to the database. The real command creates a new schema or verifies that an existing schema is compatible; it does not reset or migrate an incompatible database.

### 5. Verify installation

```bash
docker compose ps
docker compose run --rm threattrace threattrace --help
docker compose run --rm threattrace threattrace db --help
```

`postgres` and `redis` should be healthy. The application container runs as an unprivileged user and exits after the requested CLI command.

## Manual Local Setup

Create an environment and install the package with the optional Velociraptor dependency:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[all]'
cp .env.example .env
chmod 600 .env
```

Configure external PostgreSQL and Redis URLs in `.env`, then initialize an empty database:

```bash
threattrace db init --dry-run
threattrace db init
threattrace --help
```

To run Ruff and the source-tree check, install the development dependency separately:

```bash
python -m pip install '.[dev]'
make check
```

## Configuration

The complete placeholder list is in [`.env.example`](.env.example). The most important variable families are:

| Family | Purpose |
| --- | --- |
| `THREATTRACE_DATABASE_*`, `THREATTRACE_POSTGRES_*` | PostgreSQL URL, connection-pool settings, and Compose database credentials. |
| `THREATTRACE_REDIS_URL` | Redis broker URL. |
| `THREATTRACE_STORAGE_*`, `THREATTRACE_MALWARE_*`, `THREATTRACE_REPORT_*` | Local runtime, archive, sample, and report paths. |
| `THREATTRACE_MALWAREBAZAAR_*` | MalwareBazaar endpoint, key, limits, retries, and cache behavior. |
| `THREATTRACE_MALSHARE_*` | MalShare endpoint, key, download directory, timeout, and limits. |
| `THREATTRACE_CAPE_*` | CAPE API endpoint, authentication, VM selection, submission, storage, and polling settings. |
| `THREATTRACE_VR_*` | Velociraptor, clients, VM, staging, network, and collection settings. |
| `THREATTRACE_CELERY_*`, `THREATTRACE_PIPELINE_*` | Worker timeouts, retry behavior, batch size, and pipeline settings. |

Keep secrets out of the repository, restrict read access to the environment file, and use an appropriate secret-management system for production deployments.

## Full Usage Flow

The pipeline is operator-driven. A typical controlled flow is:

1. Configure storage, database, Redis, and only the external services required for the intended workflow.
2. Initialize and verify the PostgreSQL schema.
3. Obtain authorized sample metadata from configured sources.
4. Explicitly request CAPE analysis in an isolated sandbox, when that infrastructure is available.
5. Process CAPE results into normalized evidence and candidate indicators.
6. Export detection data or generate artifact inputs for review.
7. Configure and run Velociraptor validation only in authorized endpoint infrastructure.
8. Review candidates, artifacts, and endpoint results before operational use.

Ingestion, CAPE submission, detection export, artifact generation, and endpoint collection are separate actions. They are not a single automatic command and require operator decisions and external-service configuration.

## CLI Reference

Start from the built-in help:

```bash
threattrace --help
threattrace db --help
threattrace ingest --help
threattrace cape --help
threattrace detection --help
threattrace vr --help
```

| Group | Available commands | Purpose |
| --- | --- | --- |
| `db` | `init`, `harden` | Initialize or harden the PostgreSQL schema. |
| `ingest` | `malwarebazaar`, `bootstrap`, `malshare`, `malshare-repair` | Acquire and register configured source metadata. |
| `cape` | `batch`, `recover`, `enrich`, `archive` | Dispatch, recover, enrich, or archive CAPE analysis work. |
| `detection` | `export`, `artifacts` | Export detection IoCs or generate Velociraptor artifact skeletons. |
| `vr` | `select`, `prepare`, `plan`, `collect`, `export`, `compare`, `revert`, `flows`, `cleanup-flows`, `status`, `process`, `batch`, `import-detections`, `network` | Run controlled Velociraptor validation helpers. |

Use command-specific `--help` before executing an operational command. Some commands have `--dry-run` support, including `db init`, CAPE enrichment and archive planning, recovery, MalShare ingestion, and selected validation workflows.

## Example Usage

This safe example initializes a new, isolated database that has already been configured and inspects the CLI without contacting malware sources or external analysis services. It does not create a disposable environment or remove database data automatically.

```bash
docker compose up -d --wait
docker compose run --rm threattrace threattrace db init --dry-run
docker compose run --rm threattrace threattrace db init
docker compose run --rm threattrace threattrace detection --help
docker compose logs postgres redis
```

Commands such as `ingest`, `cape batch`, and Velociraptor collection require configured infrastructure and explicit operator authorization. They are not part of this example.

## Docker Compose

| Service or profile | Behavior |
| --- | --- |
| `postgres` | PostgreSQL 17 with a healthcheck and the persistent `postgres-data` volume. |
| `redis` | Redis with AOF persistence, a healthcheck, and the persistent `redis-data` volume. |
| `cli` profile | Enables the short-lived `threattrace` CLI service and its runtime-data permission initializer. |
| `workers` profile | Enables the Celery `worker` service and its runtime-data permission initializer. |
| `runtime-data` volume | Stores runtime directories used by the application; protect it because an operator may explicitly place sensitive analysis material there. |

The Compose networks keep PostgreSQL and Redis on an internal backend network. The CLI and worker also use an external-services network for user-configured external endpoints. No database or Redis port is published to the host.

Useful lifecycle commands:

```bash
docker compose ps
docker compose logs postgres redis
docker compose --profile workers up -d worker
docker compose logs -f worker
docker compose down                 # keeps named volumes
docker compose up -d --wait
```

To remove only this project's persistent volumes after backing up data you need:

```bash
docker compose down --volumes
```

Do not use broad Docker prune commands. Default Compose startup does not execute CAPE, Velociraptor, or malware operations automatically.

## Validation Performed

The published workflow validates:

- dependency installation;
- Ruff checks;
- Python compilation;
- wheel construction;
- clean wheel installation;
- package import and CLI help commands;
- `pip check`; and
- `pip-audit`.

The Docker deployment was also validated with a real image build, healthy PostgreSQL and Redis containers, CLI execution, schema initialization, persistence across container restart, and unprivileged application execution.

Limits of that validation:

- no complete CAPE and Velociraptor integration run is demonstrated by this public release;
- no new malware sample was executed during Docker validation; and
- external-service availability depends on each user's configuration and authorization.

## Legal Notice

ThreatTrace is for defensive, educational, and authorized analysis only. You are responsible for complying with applicable law, organizational policy, and the terms and rate limits of external services.

## Disclaimer

Candidate IoCs require interpretation. Generated artifacts require review. Results do not guarantee complete detection, and an observed indicator does not by itself establish causality or attribution. The safety of an analysis environment depends on its isolation and configuration.

## Data Sources Warning

MalwareBazaar and MalShare are independent external services. Their APIs, quotas, availability, and response formats can change. Treat their data as third-party intelligence and validate it in context.

CAPE and Velociraptor are also configured and maintained independently from this repository.

## Security Notes

- Never commit credentials or `.env` files.
- Isolate malware-analysis and endpoint-validation environments from production.
- Review generated detection artifacts before deployment.
- Restrict PostgreSQL and Redis access to trusted systems.
- Do not enable workers for sensitive queues before reviewing configuration and queued work.
- Protect runtime volumes that may contain sample material or reports.
- Use only systems, services, and endpoints that you are authorized to operate.
