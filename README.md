# Lotus

Lotus is an experimental codebase audit and triage platform for security researchers and product security teams, developed through security research and iterative testing. AI assists lab planning, test selection and analysis; supported dynamic tools run in a local lab, with results and coverage gaps carried into interactive reports.

<img width="457" height="834" alt="lotus-diagram" src="https://github.com/user-attachments/assets/02e7d46c-6598-4040-9792-a56460ffa385" />

[Features](#features) · [Quickstart](#quickstart) · [Web UI](#web-ui) · [Audits](#audit-workflow) · [Interactive reports](#interactive-reports) · [Deployments](#deployment-inventory) · [API / SDK](#api-and-sdk) · [Architecture](#architecture-and-isolation) · [Setup](#deployment-options) · [Operations](#operations) · [Python / export](#python-environment-and-source-export)

## Features

* Audit a Git revision with indexed source, analyzer output and traceable leads.
* Use AI to prioritize investigation, propose supported lab setups, review results and suggest fixes.
* Add a second provider to independently review findings and scoring during triage. It does not plan or approve lab builds.
* Test supported applications in local Pods with checked network restrictions.
* Explore source, coverage, findings and saved command output in interactive reports.
* Export reports as Markdown or PDF, and saved artifacts as ZIP.
* Monitor branch changes, reuse previous results as leads, and manage built-in and learned review methods.
* Compare approved, source-supported GET responses to identify possible deployments separately from vulnerability findings.

## Quickstart

From a local checkout on macOS or Linux, first follow [Install dependencies](#install-dependencies). You need Python 3.9+ with `venv`, curl, Docker with a running local engine, kind and kubectl. No application Python packages, Node.js or Go are needed on the host. Docker hosts the local Kind node; audits and labs run in Kubernetes. An existing-cluster option needs no Docker.

```sh
export PATH="$HOME/.local/share/lotus/bin:$PATH"
./lotus up --check
./lotus up
```

Run these commands from the directory containing `lotus` and `README.md`. `--check` checks prerequisites and capacity without installing tools or creating resources. Continue with `up` only after it succeeds. `up` installs pinned PyYAML in a private environment if needed, builds Lotus, creates a new Kind cluster with Calico, checks network restrictions, deploys the app and opens a foreground UI connection.

1. Open http://127.0.0.1:8000.
2. In Settings → AI Model Source, save your provider/key, load models, select a text model and use Save & Test.
3. In Start, enter a public HTTPS Git URL, select a branch and depth, then Add & Scan.
4. Follow task updates, open the console and inspect coverage. Open Report when the audit finishes.

The interactive coverage map on Start is off by default. Enable Show coverage map on Start in Settings when needed; audit coverage tracking and report coverage remain active.

A successful primary-model completion test unlocks Start. Secondary-provider problems are handled when triage needs that review. Local paths are unsupported. Branch suggestions are limited to 512; an exact branch beyond the list can be entered and verified.

Once setup reaches the foreground UI connection, Ctrl-C closes that connection while Lotus remains deployed. Reconnect with:

```sh
./lotus serve --state .lotus-local/quickstart
```

Setup defaults to a 6 GiB / 3 CPU node. The precheck requires another 1 GiB / 1 CPU beyond that allocation and considers current container memory use. The controller limit is 4 GiB; builds and optional analyzers need additional capacity. Cold image builds download dependencies and can take substantial time. No hosted Lotus release image is supplied.

The launcher preserves existing installations and does not resize Docker. A complete clean-machine installation is not yet qualified; passing setup tests and readiness checks do not guarantee that every target application can build and start.

## Web UI

| Tab | What to do |
| --- | --- |
| Start | Launch an audit; follow tasks, console output and coverage. |
| Dashboard | Find active audits and inspect history. |
| Findings | Review leads and confirmed findings, including their source. |
| Reports | Read results, export artifacts and open the command workbench. |
| Deployments | Manage hosts and compare approved identity requests. |
| Auto | Monitor branch changes and configure bounded follow-up work. |
| Settings | Configure AI providers, audit defaults, resource budgets and notifications. |
| Capabilities | Enable tools, review methods and learned skills. |
| Debug | Inspect diagnostics and manage platform resets. |

## Audit workflow

| Phase | Work performed | Result |
| --- | --- | --- |
| Discovery | Clone/index source, run enabled analyzers and prepare a supported lab. | Leads, code maps and a testing plan. |
| Analysis | Use artifacts generated in Phase 1 (Discovery) to review source and run supported checks and tools against the application. | Recorded results and remaining coverage gaps. |
| Triage / report generation | Analyze leads, review findings and scoring, evaluate lab proof and impact, suggest fixes and publish. | Confirmed findings, retained leads and an audit report. |

A lead is a potential issue. It becomes a finding only when source-matching lab proof and reporting requirements pass. Source review, simulations and application tests remain separate; a completed audit can still have incomplete validation.

### Follow and control work

* Click tasks or console summaries for saved output, source and diagnostics.
* Expand the coverage map to see checked and untested areas. It begins collapsed and automatically expands only after both audit and coverage completion.
* Stop pauses. Cancel prevents new work and drains owned processes, child audits and labs; cancellation stays pending until cleanup is verified.
* Configure/retry opens an eligible task's recovery options. Saving settings alone does not rerun work; ended audits need a fresh replay.
* If required AI access fails, repair and test the provider, then explicitly resume. Lotus does not replace required AI work with heuristic output.
* Enable plan approval to review Phase 2 before testing. Console Chat can guide planning at a safe boundary.

Settings → Audit phases → Phase 3 offers strict coverage, a narrower resource-gap exception, or completion with disclosed gaps. None bypass source integrity, isolation or finding proof checks. Unresponsive processes, ownership conflicts or failed cleanup may still require intervention.

### Tune the audit

* Depth 1–5 changes eligible analysis and bounded review effort. Start's slider applies to that audit; Settings supplies the default. Disabled tools, saved caps and runtime limits still apply.
* Optional expensive or unreliable analyzers start disabled. Settings → Analyzer resources explains requirements; enabling a tool does not create node memory or capacity.
* Prior audit context treats older artifacts as leads requiring fresh validation against the new revision.
* Disabled skills are excluded from audit context. Learned lessons are guidance, not findings or a measured guarantee of better discovery.
* Continuous Coverage polls branch changes and queues fresh audits. It avoids overlapping active work; unchanged failed/cancelled revisions are not retried automatically.
* Auto's optional loop uses supported HTTP/CLI lab checks with a budget. It is not a general repair engine for arbitrary test programs.
* Dependency source capture is separately disabled by default and currently supports bounded exact Go declarations. Missing/private/unsupported sources remain gaps. Up to the configured number of eligible dependency audits use their own queue, source, results and runtime; shared parent labs are not implemented.

Displays use MiB/GiB/TiB; compatibility API fields ending in `_mb` retain MiB values. Filesystem pressure can include shared storage. Audit limits, controller memory and analyzer Pod limits are separate settings.

## Interactive reports

Reports provide a notebook-like workbench alongside a concise audit summary. Start with the outcome, areas reviewed, unverified areas and next steps, even when no findings were confirmed.

* Review leads, browse source and inspect coverage for that report's exact audit.
* Read recorded architecture/behavior diagrams and comparisons where artifacts support them. Missing specifications or component details remain unknown.
* Open notebook to inspect or add supported command cells and view their output. Commands run only when explicitly requested.
* Use Repro when runnable cells exist; reports without findings use Run commands where applicable. No empty reproduction button is shown.
* Download Markdown, PDF, or saved artifacts as ZIP. The ZIP lists omissions and is not a full source/image/dependency backup.

### Work with the local lab

1. Before scanning, enable Settings → Advanced Settings → Keep lab running after scan.
2. Open the report's notebook and choose Connect recorded lab.
3. Run supported commands and inspect output. Lotus checks the audit, source, Pod/container and immutable runtime identity before and after execution.
4. Stop the owned lab when finished.

A stopped or replaced lab cannot be substituted with another audit's latest Pod. Historical reports remain readable, but Kubernetes historical reconstruction is not implemented. Fresh replay creates a new audit and new results. Docker reattachment needs a retained, source-matching immutable runtime capsule and can fail when dependencies are unavailable.

Saved command observations do not automatically confirm a finding. Editing Markdown saves a draft; it does not rewrite the signed publication or its exports. Optional host Python execution has syntax/resource limits, not an OS sandbox. Notebook access is privileged operator access; shared use requires further review.

## Deployment inventory

This feature identifies possible deployments; it does not run vulnerability payloads or create Leads/Findings.

1. Choose an audit, add hosts/domains and save the inventory.
2. Discover Hosts collects in-scope names from public CT/Wayback sources without API keys. Refresh preserves provenance and partial outcomes.
3. Review requests, select or replace eligible GET paths, edit purposes and Save plan. Saving sends no requests.
4. Choose Test local lab, inspect the selected runtime URL and saved GET plan, then Run local lab test. It captures a baseline and compares a second response from that same lab. Verify enabled hosts is a separate action.
5. View fingerprint opens that operation's saved markers, HTTP statuses, body hashes and heuristic confidence. Host counts, endpoints, machine matches and manual results are shown separately.

Test local lab requires an already running, source-bound Kubernetes lab and eligible source-supported requests. The preview sends no target requests; its cluster/service URL is not a browser connection. Two matching observations do not prove a source revision or a vulnerability, and no findings are created. Historical results remain tied to their recorded operation even when a newer baseline is saved.

Plan edits invalidate earlier baselines and assessments. Requests have no query strings, bodies, credentials or custom headers. Active checks use destination-restricted Kubernetes workers with bounded output, pinned addresses, no redirects or environment proxies, a measured denial control and verified cleanup.

The request catalog supports literal Python GET responses, explicitly mapped static metadata and verified native lab health responses on nine conventional paths. Observed health requests require explicit selection and review before use. Arbitrary dynamic routes, general private-LAN URLs and POST-only interfaces are unsupported. Owned local Kubernetes bindings support local testing. Confidence is a heuristic estimate; it does not establish an exact remote revision, ownership or complete discovery.

Limits: 50 discovery domains, 1,000 retained results and 200 enabled identity hosts. Active identity checks have no equivalent Docker implementation; passive discovery uses a separate collector.

## API and SDK

The app serves `/openapi.json`, `/docs` and `/redoc`. Use exact audit IDs when reading progress, source or reports. Some compatibility fields retain `evidence` in their names; they mean saved results/artifacts, not exhaustive proof.

### Start and inspect an audit with curl

After AI verification, replace the example URL with your repository and use this instead of Add & Scan. Set `LOTUS_AUTH_TOKEN` through a private environment only when authentication is enabled. The helper sends its value through curl input, avoiding credential values in process arguments; curl needs `--fail-with-body` and `--header @-` support.

```sh
export LOTUS_URL=http://127.0.0.1:8000
lotus_api() {
  if [ -n "${LOTUS_AUTH_TOKEN:-}" ]; then
    printf 'Authorization: Bearer %s\n' "$LOTUS_AUTH_TOKEN" |
      curl --fail-with-body --silent --show-error --connect-timeout 5 --max-time 60 --header @- "$@"
  else
    curl --fail-with-body --silent --show-error --connect-timeout 5 --max-time 60 "$@"
  fi
}
lotus_api "$LOTUS_URL/api/ai/readiness"
lotus_api -H 'Content-Type: application/json' \
  --data '{"source":"https://github.com/YOUR-ORG/YOUR-REPO","branch":"main","audit_depth":3}' \
  "$LOTUS_URL/api/repos/enroll-and-scan"
```

Keep the returned `repo.id` and `scan.job_id`; substitute them for the placeholders below:

```sh
REPO_ID='<repo.id>'
JOB_ID='<scan.job_id>'
lotus_api "$LOTUS_URL/api/scan-jobs/$JOB_ID?include_output=false"
lotus_api "$LOTUS_URL/api/repos/$REPO_ID/progress?job_id=$JOB_ID&include_coverage_map=false"
lotus_api "$LOTUS_URL/api/scan-jobs/$JOB_ID/sources?offset=0&limit=20"
lotus_api "$LOTUS_URL/api/scan-jobs/$JOB_ID/recovery"
```

To cancel this specific audit, explicitly run the following, then poll until cleanup settles:

```sh
lotus_api -X POST "$LOTUS_URL/api/repos/$REPO_ID/scan/cancel?job_id=$JOB_ID"
```

Repeat lightweight reads while work runs. Each HTTP wait is bounded to 60 seconds; a timeout does not cancel server work. Repeated enrollment attaches to the same active audit; enrollment after it ends starts a new one. Source reads return 409 until immutable capture exists; index preparation can still be pending. Recovery may require a provider, plan or coverage decision.

For reports, read `GET /api/reports`, then `GET /api/reports/{report_id}` and match `report_context.binding.scan_job_id`. Download that report's `/markdown`, `/pdf` or `/artifacts.zip` using `lotus_api --output FILE URL`. Never substitute another audit's latest report. The schema covers remaining settings, triage and notebook requests; notebook execution requires explicit runtime context.

### Python SDK

Install the locked dependencies in [Python environment and source export](#python-environment-and-source-export), then run from the repository root:

```python
import os
from backend.sdk import LotusClient
from backend.sdk.exceptions import LotusTimeoutError

with LotusClient(base_url=os.getenv("LOTUS_URL", "http://127.0.0.1:8000"),
                 token=os.getenv("LOTUS_AUTH_TOKEN")) as client:
    repo = client.add_repo("https://github.com/YOUR-ORG/YOUR-REPO", branch="main")
    accepted = client.scan_repo(repo.id, audit_depth=3)
    job_id = accepted["job_id"]
    print("Audit", job_id, client.get_scan_status(job_id).status)
    try:
        print(client.wait_for_scan(repo.id, job_id=job_id, timeout=900))
    except LotusTimeoutError:
        # Ending the client wait does not cancel the audit.
        print(client.get_audit_progress(repo.id, job_id=job_id))
```

The SDK is repository-local, not a published package. It covers enrollment, monitoring, findings, source/progress and explicit recovery; deployment management and SSE are not included. A client timeout ends the wait, not the audit. Use lightweight progress instead of repeatedly downloading full scan details.

Recovery actions require current eligibility, checkpoint/configuration revision and an idempotency key. On conflict, inspect current state before retrying; reuse a key only for the same logical request.

### API access

`LOTUS_AUTH_TOKEN` is a shared operator token, separate from AI keys. Protected REST/SSE accept Bearer or `X-API-Key` headers. There are no individual accounts, scoped roles or tenant isolation.

* Loopback single-user mode can run without authentication. Shared exposure requires authentication, TLS and additional review.
* Settings → API Access starts disabled. Its toggle enables browser controls, not server authentication.
* Generate creates a masked, temporary token from 32 random bytes. It does not install or persist the server token. Connect verifies it before changing the browser credential.
* Install/rotate tokens through private bootstrap configuration or the authoritative Secret, restart all controller processes after draining work, then reconnect clients. Secret updates alone do not restart Pods; no dual-token grace exists.
* Health, readiness, metrics and minimal auth status remain public. Keep credentials out of URLs, process arguments, Git, logs and issues.

## Architecture and isolation

| Component | Responsibility |
| --- | --- |
| `frontend/index.html` | Served vanilla-JavaScript UI. The React prototype is inactive. |
| `backend/main.py`, `backend/api.py` | FastAPI routes, settings and durable state. |
| `backend/scan_worker.py`, `backend/pipeline.py` | Queue/leases, task coordination and audit phases. |
| `backend/phase2.py`, coverage/proof/report modules | Separate source review, runtime tests and published findings. |
| Kubernetes providers and builder | Source-bound images, restricted workloads and ownership-aware cleanup. |
| Database and managed files | SQLite/PostgreSQL records, source snapshots and saved artifacts. |

Local single-instance SQLite is the primary setup. PostgreSQL or enterprise overlays require additional shared-storage, authentication and lifecycle qualification; PostgreSQL alone does not provide multi-tenancy.

### Network boundary

* The quickstart creates fresh Kind with kindnet disabled and Calico installed. Stock kindnet alone does not enforce NetworkPolicy; Lotus refuses execution when isolation checks fail. There is no equivalent bypass that makes a non-enforcing CNI safe.
* Before source transfer or repository commands, a trusted init gate measures allowed/denied connections from the actual Pod and checks policy/ownership.
* Application labs deny outbound traffic from startup. Dependencies are installed while building source-embedded images, not during isolated lab startup.
* Builders and eligible download tools allow public IPv4 TCP 80/443, exact cluster DNS and an owned registry exception. This is not a no-internet sandbox or an exfiltration guarantee for repository build scripts.
* Execution Pods are nonroot/tokenless, with no host mounts or daemon sockets. Kaniko's builder namespace permits the baseline security level needed to unpack images.
* Only private, single-stack IPv4 Pod networks are supported. Finite traffic checks do not certify all network paths, kernel isolation or future CNI behavior.

## Deployment options

Every helper has `--help`. No command below changes an existing cluster's CNI.

### Install dependencies

Install the host prerequisites once, then return to [Quickstart](#quickstart). Skip packages you already have. Run Lotus as your normal user.

#### macOS

On a fresh Mac, install [Homebrew](https://brew.sh/) first if you want to use the terminal commands below. Its installer may prompt for your password and Apple's Command Line Tools; finish those prompts before continuing.

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
if [ -x /opt/homebrew/bin/brew ]; then
  eval "$(/opt/homebrew/bin/brew shellenv)"
else
  eval "$(/usr/local/bin/brew shellenv)"
fi
```

Skip the Homebrew installer if it is already installed. If Python 3.9+ is missing, install it and select that interpreter:

```sh
brew install python@3.12
export LOTUS_PYTHON="$(brew --prefix python@3.12)/bin/python3.12"
```

If Docker Desktop is missing, install it, then open it and finish its first-run setup. Wait until `docker info` succeeds. These are the [Homebrew Docker Desktop commands](https://formulae.brew.sh/cask/docker-desktop):

```sh
brew install --cask docker-desktop
open -a Docker
docker info
```

Without Homebrew, use the [Python installer](https://www.python.org/downloads/macos/) and [Docker Desktop installer](https://docs.docker.com/desktop/setup/install/mac-install/) instead. An unwritable Homebrew directory does not need to be changed for the kind/kubectl installation below.

In Docker Desktop → Settings → Resources, allocate at least 8 GiB memory and 4 CPUs for a fresh installation with no other containers. More running containers need more headroom. Apply the changes, wait for Docker to restart, then continue with the kind/kubectl commands below. Docker Desktop's built-in Kubernetes does not need to be enabled.

#### Ubuntu / Debian

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv ca-certificates curl git
```

Install Docker Engine using the official [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) or [Debian](https://docs.docker.com/engine/install/debian/) repository instructions. After adding that repository, install and start the packages:

```sh
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in before continuing, then run `docker info` without sudo. Docker group membership grants host-level privileges; see [Docker's post-installation instructions](https://docs.docker.com/engine/install/linux-postinstall/). Other Linux distributions need their equivalent Python/venv packages and Docker installation.

#### kind and kubectl, without administrator access

Run this block on macOS or Linux. It downloads official release binaries, verifies their published SHA-256 checksums, and installs them in your own Lotus tools directory. The versions match the pinned local setup: kind 0.27.0 and Kubernetes 1.32.2. For an existing cluster, use a kubectl version [compatible with that cluster](https://kubernetes.io/releases/version-skew-policy/#kubectl).

```sh
(
  set -eu
  case "$(uname -s)" in Darwin) lotus_os=darwin ;; Linux) lotus_os=linux ;; *) exit 1 ;; esac
  case "$(uname -m)" in arm64|aarch64) lotus_arch=arm64 ;; x86_64) lotus_arch=amd64 ;; *) exit 1 ;; esac
  lotus_tmp=$(mktemp -d)
  trap 'rm -rf "$lotus_tmp"' EXIT
  lotus_kind_url="https://github.com/kubernetes-sigs/kind/releases/download/v0.27.0/kind-$lotus_os-$lotus_arch"
  lotus_kubectl_url="https://dl.k8s.io/release/v1.32.2/bin/$lotus_os/$lotus_arch/kubectl"
  curl -fL --retry 3 --connect-timeout 15 --max-time 180 "$lotus_kind_url" -o "$lotus_tmp/kind"
  curl -fL --retry 3 --connect-timeout 15 --max-time 60 "$lotus_kind_url.sha256sum" -o "$lotus_tmp/kind.sha256"
  curl -fL --retry 3 --connect-timeout 15 --max-time 180 "$lotus_kubectl_url" -o "$lotus_tmp/kubectl"
  curl -fL --retry 3 --connect-timeout 15 --max-time 60 "$lotus_kubectl_url.sha256" -o "$lotus_tmp/kubectl.sha256"
  "${LOTUS_PYTHON:-python3}" - "$lotus_tmp" <<'PY'
import hashlib, pathlib, re, sys
directory = pathlib.Path(sys.argv[1])
for name in ("kind", "kubectl"):
    expected = (directory / (name + ".sha256")).read_text().split()[0]
    actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or actual != expected:
        raise SystemExit(name + ": checksum verification failed; nothing installed")
    print(name + ": checksum verified")
PY
  mkdir -p "$HOME/.local/share/lotus/bin"
  install -m 0755 "$lotus_tmp/kind" "$HOME/.local/share/lotus/bin/kind"
  install -m 0755 "$lotus_tmp/kubectl" "$HOME/.local/share/lotus/bin/kubectl"
)
export PATH="$HOME/.local/share/lotus/bin:$PATH"
kind version
kubectl version --client
```

Repeat the `export PATH` line in each new terminal, or add it once to your shell's startup file. These commands follow the [kind binary installation](https://kind.sigs.k8s.io/docs/user/quick-start/#installing-from-release-binaries) and [kubectl checksum verification](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux) procedures.

Before running `./lotus up --check`, ensure Docker has at least 7 GiB currently free and 4 CPUs available to its engine for the default node. On Docker Desktop, adjust [Settings → Resources](https://docs.docker.com/desktop/settings-and-maintenance/settings/#resources) if needed; existing containers also consume memory. A passing precheck does not run a build or prove that a fresh installation will succeed.

### More local capacity or an existing cluster

```sh
./lotus up --check --state '<new-private-directory>' --name lotus-netpol-research \
  --node-memory-gib 8 --node-cpus 4 --port 8001
# Repeat without --check to create the new installation.

./lotus up --context '<existing-context>' \
  --image '<registry>/lotus@sha256:<64-hex-digest>'
```

* Existing clusters need an enforcing CNI, persistent storage, node registry trust and installation permissions. This route needs no Docker or node modification.
* Add `--kubeconfig PATH` or `--local-preloaded` as needed. `--no-serve` finishes after readiness.
* `up` refuses existing state, same-named Kind clusters and existing Lotus namespaces. Use `serve --state PATH` to reopen an installation.
* Failed setup preserves private state and uncertain resources for inspection. Do not delete ownership records or blindly repeat setup over them.

### Interrupted setup

Ctrl-C during installation stops setup and preserves its state and any resources already created. It does not roll back the installation. `kind delete clusters --all` removes Kind clusters, but can leave the custom Docker networks Lotus created.

* `--check` detects an existing cluster, setup directory or same-named Docker network before the application image is built.
* Inspect a failed attempt's `quickstart.json`, `cluster/setup.log` and `cluster/ownership.json` in its state directory. An early failure may not have created every file.
* Preserve that directory until cleanup is complete. A new attempt needs an unused cluster name and a new state directory; a completed installation uses `serve` instead.

After stopping any resources from the interrupted attempt that still consume capacity, try a separate installation:

```sh
./lotus up --check --name lotus-netpol-retry --state .lotus-local/retry
./lotus up --name lotus-netpol-retry --state .lotus-local/retry
```

Choose another name and directory if those already exist. Setup never deletes or reuses an unknown network automatically.

### Manual Kubernetes setup

Build the root Dockerfile with a compatible builder and publish/preload its immutable Linux amd64/arm64 image. No Docker daemon is needed for Kubernetes audit execution.

```sh
python3 scripts/configure_local.py
python3 scripts/deploy_kubernetes.py \
  --context '<existing-context>' \
  --image '<registry>/lotus@sha256:<64-hex-digest>'
python3 scripts/serve_kubernetes.py --context '<existing-context>'
```

Configuration creation refuses to overwrite an existing `.env`. Deployment imports private configuration and installs builder RBAC. `--render-only PATH` emits a manifest containing a Secret; do not commit it.

Source builds require the `lotus-build` namespace, registry storage, NodePort 30500 and containerd trust for the observed registry node's HTTP address. Administrators manage trust on existing nodes. This path does not configure an external TLS/authenticated registry.

| Variable | Purpose |
| --- | --- |
| `LOTUS_K8S_LAB_IMAGE` | Source-matching immutable application image. |
| `LOTUS_K8S_LAB_BASE_IMAGE` | Optional digest-pinned approved toolchain base; target source is built separately. |
| `LOTUS_K8S_KANIKO_REQUEST_MEM` | Build reservation; defaults to 768 MiB. |
| `LOTUS_K8S_KANIKO_MEM` | Build memory limit; defaults to 4 GiB. |

Supported native recipes validate source, executable paths and architecture. Exact supported Node/pnpm pins use checksum-verified official packages; Go declarations in root go.mod/go.work select a release through the official Go proxy and checksum database, with installed version and architecture checks. Other toolchains, external services and unsupported version declarations can still block setup. Increasing memory does not correct an invalid recipe.

CLI security testing and fuzzing are opt-in in Settings. Parser fuzzing, runtime/dependency fuzzing and native fuzzing have separate controls; all are off by default to keep typical audits responsive. Excluded tests remain visible as coverage gaps. Static analysis, supported local lab validation, triage and reporting remain available.

Native C/C++ and Rust fuzzing currently requires the Docker runtime. It is disabled by default and skipped on Kubernetes, with the missing coverage recorded. Other analysis and supported local lab checks can continue.

For manual fresh Kind setup, use `scripts/bootstrap_kind.py`; its default is plan-only and `--create` makes the new cluster. Use `k8s/verification/network_policy_preflight.py` to measure policy after infrastructure changes. Both require explicit context/image/ownership inputs; see their `--help`.

### Docker backup

For the Docker backup, run a native controller on the Docker daemon's host with `LOTUS_RUNTIME=docker` and `LOTUS_LAB_PROVIDER=docker`. Leave `LOTUS_DISABLE_LAB` unset. Configure its environment privately; native startup does not load Compose's `.env` automatically.

Compose application startup is supported, but the socket-mounted single-Compose controller has an unresolved lab loopback/connectivity gap. Complete audits in that topology are not qualified. Docker access is privileged host authority; never share one SQLite directory between controllers.

## Operations

* Persist managed data plus encryption/proof-signing keys. Use consistent database backups; a database backup does not include every source snapshot or runtime image.
* Restore only while idle. Review restored settings and explicitly restart scheduling.
* Reset Platform prioritizes cancellation, drains owned work and removes managed audits, source, reports, notebooks, deployments, scratch and backups. It keeps configuration, credentials and default/learned skills.
* Full Reset also clears managed configuration, credentials, learned skills and tool state. Default skills remain; external environment values, Secrets and infrastructure stay operator-managed.
* Cleanup preserves unrelated/replaced resources. Docker image cleanup removes only unused generated images with verified ownership. Registry blobs and node/build caches remain runtime-managed; reset does not broadly prune Docker or promise reclaimed physical cache space.
* Keep one SQLite controller. Upgrades drain work, back up, preserve PVC/keys and deploy an immutable image. SQLite uses Recreate with an interruption. Check readiness and restart counts afterwards.

A manifest omitting an existing HPA does not delete it. For a verified single-instance maintenance boundary:

```sh
kubectl --context '<existing-context>' -n lotus delete hpa lotus --ignore-not-found
```

Cancellation or reset can remain blocked by foreign ownership, finalizers or incomplete cleanup. A crash during filesystem/database deletion is uncertain; review the recorded status before retrying.

## Python environment and source export

For the repository-local SDK or a native backend, use Python 3.12 and install the locked dependencies below. The setup launcher supports Python 3.9+ and manages its own setup environment.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r backend/bootstrap.requirements.lock
python -m pip install --require-hashes -r backend/requirements.lock
python -m pip check
```

* Use Debug → Run Tests for database and runtime checks plus the focused test battery in an isolated lab. The selected runtime must be available; a skipped test is not a pass.
* This runtime checkout retains those diagnostic tests. Full development and browser test suites are excluded.

Create a separate source-only export:

```sh
python3 scripts/export_public_source.py --output ../lotus-source-review
```

The exporter excludes private runtime data and checks the copied files for recognized secrets, personal-data indicators and audit records. It stops on unresolved review items and leaves the live installation untouched. Detection is finite; review the exported folder before publishing. It does not initialize Git, commit or upload.

Current limits include unsupported multi-service/daemon-socket setups, incomplete dependency capture, finite analyzer/review budgets and no shared dependency labs. Working APIs or a generated report do not establish exhaustive security coverage or universal repository support.

Intended for legitimate security research. Further development and testing are needed before production use. Provided “as is,” without warranty or liability, under the [MIT License](LICENSE). Dependency licenses and the bundled [font notice](backend/assets/fonts/LICENSE.txt) still apply.
