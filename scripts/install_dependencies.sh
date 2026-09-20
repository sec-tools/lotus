#!/bin/sh
# Missing-tool bootstrap only. Kubernetes resources and Docker settings are not changed.
set -eu

lotus_tools_path() {
    for lotus_dir in /usr/local/bin /opt/homebrew/bin /Applications/Docker.app/Contents/Resources/bin "$HOME/Applications/Docker.app/Contents/Resources/bin" "$HOME/.docker/bin" "$HOME/.local/share/lotus/bin"; do
        if [ -d "$lotus_dir" ]; then PATH="$PATH:$lotus_dir"; fi
    done
    if [ -d "$HOME/.local/share/lotus/bin" ]; then PATH="$HOME/.local/share/lotus/bin:$PATH"; fi
    export PATH
}
lotus_tools_path
lotus_fail() { printf '%s\n' "Lotus dependencies: $*" >&2; exit 1; }
lotus_python_works() {
    lotus_python_path=$(command -v "$1") || return 1
    # Apple's /usr/bin shim can request Command Line Tools rather than run Python.
    # Detect missing developer tools without executing that shim or opening a GUI.
    if [ "$(uname -s)" = Darwin ] && [ "$lotus_python_path" -ef /usr/bin/python3 ]; then
        lotus_developer_dir=$(xcode-select -p 2>/dev/null) || return 1
        [ -d "$lotus_developer_dir" ] || return 1
    fi
    "$1" -c 'import sys, venv, ensurepip; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}
lotus_python() {
    if [ -n "${LOTUS_PYTHON:-}" ]; then
        lotus_python_works "$LOTUS_PYTHON" || return 1
        command -v "$LOTUS_PYTHON"
        return 0
    fi
    for lotus_python_name in /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
        if lotus_python_works "$lotus_python_name"; then command -v "$lotus_python_name"; return 0; fi
    done
    return 1
}
lotus_kubectl_compatible() {
    lotus_client_python=$(lotus_python) || return 1
    "$lotus_client_python" -c 'import json, re, subprocess, sys
try:
    result = subprocess.run(["kubectl", "version", "--client", "-o", "json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    version = json.loads(result.stdout).get("clientVersion", {}).get("gitVersion", "")
    match = re.fullmatch(r"v1\.(\d+)\.\d+(?:[-+][0-9A-Za-z.-]+)?", version)
    sys.exit(0 if result.returncode == 0 and match and 31 <= int(match[1]) <= 33 else 1)
except (OSError, ValueError, AttributeError, subprocess.TimeoutExpired):
    sys.exit(1)'
}
lotus_probe_docker() {
    "$lotus_ready_python" -c 'import subprocess, sys
try:
    result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    sys.exit(result.returncode)
except (OSError, subprocess.TimeoutExpired):
    sys.exit(1)'
}
lotus_local_docker_context() {
    "$lotus_ready_python" -c 'import json, os, subprocess, sys
context = os.environ.get("DOCKER_CONTEXT")
host = os.environ.get("DOCKER_HOST")
def refuse():
    print("Lotus dependencies: The selected Docker context is unavailable, remote, or conflicts with DOCKER_HOST. Select an existing local context or correct DOCKER_CONTEXT/DOCKER_HOST, then retry. Existing contexts and settings were preserved.", file=sys.stderr)
    sys.exit(1)
if host and not host.startswith("unix://"):
    refuse()
if host and not context:
    sys.exit(0)
try:
    args = ["docker", "context", "inspect"] + ([context] if context else []) + ["--format", "{{json .Endpoints.docker.Host}}"]
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    endpoint = json.loads(result.stdout)
    if result.returncode or not isinstance(endpoint, str) or not endpoint.startswith("unix://") or (host and host != endpoint):
        refuse()
except (OSError, ValueError, subprocess.TimeoutExpired):
    refuse()'
}
lotus_usage() {
    printf '%s\n' 'Usage: ./lotus deps [--existing-context]' \
        'Install missing Mac tools: Python 3.9+ (venv/ensurepip), Docker Desktop,' \
        'kind 0.27.0 and kubectl 1.32.2. Existing tools are preserved.' \
        '--existing-context installs only Python and kubectl; Docker is not used.' \
        'Homebrew and Docker first-run prompts may require your interaction.'
}
lotus_mode=install
lotus_local=1
for lotus_arg in "$@"; do
    case "$lotus_arg" in
        --existing-context) lotus_local=0 ;;
        --check) lotus_mode=check ;;
        --python) lotus_mode=python ;;
        --help|-h) lotus_usage; exit 0 ;;
        *) lotus_fail "Unknown option: $lotus_arg. Run ./lotus deps --help." ;;
    esac
done
if [ "$lotus_mode" = python ]; then
    lotus_python || lotus_fail 'A complete Python 3.9+ is required. Run ./lotus deps, or set LOTUS_PYTHON to an interpreter with venv and ensurepip.'
    exit 0
fi
lotus_missing=
lotus_python >/dev/null 2>&1 || lotus_missing=python
for lotus_name in kubectl; do
    command -v "$lotus_name" >/dev/null 2>&1 || lotus_missing="$lotus_missing $lotus_name"
done
if [ "$lotus_local" = 1 ]; then
    lotus_kubectl_compatible || lotus_missing="$lotus_missing compatible-kubectl"
    for lotus_name in kind docker; do
        command -v "$lotus_name" >/dev/null 2>&1 || lotus_missing="$lotus_missing $lotus_name"
    done
    if [ "$lotus_mode" = check ]; then
        if ! lotus_ready_python=$(lotus_python) || ! command -v docker >/dev/null 2>&1 \
                || ! lotus_local_docker_context >/dev/null 2>&1 || ! lotus_probe_docker; then
            lotus_missing="$lotus_missing ready-local-engine"
        fi
    fi
fi
if [ "$lotus_mode" = check ]; then [ -z "$lotus_missing" ]; exit $?; fi
[ "$(uname -s)" = Darwin ] || lotus_fail 'Automatic dependency installation supports macOS. On Linux, install the README prerequisites with your package manager.'
[ "$(id -u)" != 0 ] || lotus_fail 'Run ./lotus deps as your normal Mac user, without sudo.'
case "$(uname -m)" in arm64) lotus_arch=arm64 ;; x86_64) lotus_arch=amd64 ;; *) lotus_fail 'Unsupported Mac architecture.' ;; esac
if [ -n "${LOTUS_PYTHON:-}" ]; then
    lotus_python >/dev/null 2>&1 || lotus_fail 'LOTUS_PYTHON is not a complete Python 3.9+ interpreter. Correct it or unset it before running ./lotus deps; it will not be overridden.'
fi
lotus_tmp=$(mktemp -d "${TMPDIR:-/tmp}/lotus-deps.XXXXXXXX")
trap 'rm -rf "$lotus_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
lotus_download() {
    curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --connect-timeout 15 --max-time 300 "$1" -o "$2"
}
lotus_brew() {
    if ! command -v brew >/dev/null 2>&1; then
        [ -t 0 ] || lotus_fail 'Homebrew installation needs an interactive terminal for Apple/admin prompts. Run ./lotus deps in Terminal.'
        printf '%s\n' 'Installing Homebrew from its official installer. Complete any Apple Command Line Tools or administrator prompts.'
        lotus_download https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh "$lotus_tmp/homebrew-install.sh"
        /bin/bash "$lotus_tmp/homebrew-install.sh" || lotus_fail 'Homebrew installation did not finish. Complete its displayed prompts, then run ./lotus deps again.'
        lotus_tools_path
        command -v brew >/dev/null 2>&1 || lotus_fail 'Homebrew was not found after installation. Follow its displayed setup instructions, then run ./lotus deps again.'
    fi
    HOMEBREW_NO_AUTO_UPDATE=1 brew "$@" || lotus_fail 'Homebrew could not install the missing dependency. Review its message above, then run ./lotus deps again; no existing permissions were changed by Lotus.'
}
if ! lotus_python >/dev/null 2>&1; then
    printf '%s\n' 'Installing a complete Python with Homebrew…'
    lotus_brew install python
    lotus_tools_path
    lotus_python >/dev/null 2>&1 || lotus_fail 'Python is still unavailable. Set LOTUS_PYTHON to the Homebrew Python executable, then retry.'
fi
lotus_install_binary() {
    lotus_binary=$1; lotus_url=$2; lotus_checksum_url=$3
    if [ "${4:-0}" = 0 ] && command -v "$lotus_binary" >/dev/null 2>&1; then return 0; fi
    lotus_dest="$HOME/.local/share/lotus/bin"
    # Do not replace an existing user file, including a broken symlink.
    [ ! -e "$lotus_dest/$lotus_binary" ] && [ ! -L "$lotus_dest/$lotus_binary" ] || lotus_fail "$lotus_binary already exists in $lotus_dest but is not executable; inspect it before retrying."
    printf '%s\n' "Downloading pinned $lotus_binary and its published SHA-256 checksum…"
    lotus_download "$lotus_url" "$lotus_tmp/$lotus_binary"
    lotus_download "$lotus_checksum_url" "$lotus_tmp/$lotus_binary.sha256"
    lotus_expected=$(awk 'NR == 1 {print $1}' "$lotus_tmp/$lotus_binary.sha256")
    [ "${#lotus_expected}" = 64 ] || lotus_fail "$lotus_binary checksum response is invalid; nothing installed."
    case "$lotus_expected" in *[!a-f0-9]*) lotus_fail "$lotus_binary checksum response is invalid; nothing installed." ;; esac
    lotus_actual=$(shasum -a 256 "$lotus_tmp/$lotus_binary" | awk '{print $1}')
    [ "$lotus_actual" = "$lotus_expected" ] || lotus_fail "$lotus_binary checksum mismatch; nothing installed."
    mkdir -p "$lotus_dest"
    lotus_stage=$(mktemp "$lotus_dest/.${lotus_binary}.XXXXXXXX")
    if ! cp "$lotus_tmp/$lotus_binary" "$lotus_stage" || ! chmod 0755 "$lotus_stage" || ! ln "$lotus_stage" "$lotus_dest/$lotus_binary"; then
        rm -f "$lotus_stage"
        lotus_fail "$lotus_binary destination changed or could not be written; existing files were preserved."
    fi
    rm -f "$lotus_stage"
    lotus_tools_path
}
lotus_kubectl_url="https://dl.k8s.io/release/v1.32.2/bin/darwin/$lotus_arch/kubectl"
lotus_pin_client=0
if [ "$lotus_local" = 1 ] && command -v kubectl >/dev/null 2>&1 && ! lotus_kubectl_compatible; then
    if [ -e "$HOME/.local/share/lotus/bin/kubectl" ] || [ -L "$HOME/.local/share/lotus/bin/kubectl" ]; then
        lotus_fail 'Local Kind 1.32 needs a working kubectl 1.31–1.33. The existing private kubectl was preserved; inspect or move it before retrying ./lotus deps. Existing-cluster mode does not impose this local version.'
    fi
    printf '%s\n' 'The current kubectl is incompatible with local Kind 1.32; preserving it and installing pinned kubectl in the private Lotus tools directory.'
    lotus_pin_client=1
fi
lotus_install_binary kubectl "$lotus_kubectl_url" "$lotus_kubectl_url.sha256" "$lotus_pin_client"
if [ "$lotus_local" = 1 ]; then
    lotus_kind_url="https://github.com/kubernetes-sigs/kind/releases/download/v0.27.0/kind-darwin-$lotus_arch"
    lotus_install_binary kind "$lotus_kind_url" "$lotus_kind_url.sha256sum"
    lotus_ready_python=$(lotus_python)
    lotus_docker_usable=0
    if command -v docker >/dev/null 2>&1; then lotus_local_docker_context; fi
    if command -v docker >/dev/null 2>&1 && lotus_probe_docker; then lotus_docker_usable=1; fi
    if [ "$lotus_docker_usable" = 0 ] && [ ! -d /Applications/Docker.app ] && [ ! -d "$HOME/Applications/Docker.app" ]; then
        printf '%s\n' 'Installing Docker Desktop with Homebrew. Complete any macOS administrator prompts.'
        lotus_brew install --cask docker-desktop
    fi
    lotus_tools_path
    command -v docker >/dev/null 2>&1 || lotus_fail 'Docker Desktop is present but its CLI is unavailable. Open Docker Desktop, finish setup, and enable its CLI tools, then run ./lotus deps again.'
    lotus_local_docker_context
    if ! lotus_probe_docker; then
        printf '%s\n' 'Opening Docker Desktop. Complete its first-run terms, security and administrator prompts.'
        open -a Docker || lotus_fail 'Open Docker Desktop manually, finish setup, then run ./lotus deps again.'
        "$lotus_ready_python" -c 'import subprocess, sys, time
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    try:
        result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=min(5, max(.01, deadline-time.monotonic())))
        if result.returncode == 0:
            sys.exit(0)
    except (OSError, subprocess.TimeoutExpired):
        pass
    time.sleep(min(2, max(0, deadline-time.monotonic())))
sys.exit(1)' || lotus_fail 'Docker is not ready. Open Docker Desktop, finish its first-run prompts, wait until docker info succeeds, then rerun ./lotus deps. No engine settings were changed.'
    fi
fi
if [ "$lotus_local" = 1 ]; then
    printf '%s\n' 'Dependencies are available. Run ./lotus up --check, then ./lotus up. Docker capacity and Kubernetes readiness are checked during setup.'
else
    printf '%s\n' 'Dependencies are available for an existing Kubernetes cluster. Run ./lotus up --context NAME --image REGISTRY/lotus@sha256:DIGEST --check, then repeat without --check. See README.md for existing-cluster prerequisites.'
fi
