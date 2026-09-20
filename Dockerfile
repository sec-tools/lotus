# Analyzer prerequisites are installed at image build time, never while an
# audit is waiting. Exact modules are verified through the public Go checksum
# database; the immutable official Go index is recorded in toolchain provenance.
FROM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS lotus-go-tools
ENV GOBIN=/opt/lotus-tools GOTOOLCHAIN=local
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0 \
    && go install golang.org/x/vuln/cmd/govulncheck@v1.8.0 \
    && go install honnef.co/go/tools/cmd/staticcheck@v0.8.1 \
    && /opt/lotus-tools/gosec -version \
    && /opt/lotus-tools/govulncheck -help >/dev/null 2>&1 \
    && go version -m /opt/lotus-tools/govulncheck \
    && /opt/lotus-tools/staticcheck -version

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

WORKDIR /app

# Match the verified local Kubernetes cluster. Override for another server
# minor version; kubectl supports a one-minor client/server difference.
ARG KUBECTL_VERSION=v1.32.2

# System packages + Java runtime (for Joern) + security tools
# Host-backed labs use the client and plugins; Debian packages them separately.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git nginx supervisor postgresql-client curl wget unzip gcc g++ libc6-dev pkg-config coreutils \
    openjdk-21-jre-headless docker-cli docker-buildx docker-compose \
    && docker --version \
    && docker buildx version \
    && docker compose version \
    && timeout --version | grep -F 'GNU coreutils' \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m -s /bin/false lotus \
    && mkdir -p /app/data /app/data/backups /var/log/nginx /var/cache/nginx /run /tmp \
    && (getent group docker && usermod -aG docker lotus || true) \
    && chown -R lotus:lotus /app /var/log/nginx /var/cache/nginx /run /tmp

# The strict Kubernetes lab provider invokes kubectl. Install the matching
# native architecture and verify the release checksum before exposing it.
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64|arm64) ;; *) echo "Unsupported kubectl architecture: $arch" >&2; exit 1 ;; esac; \
    curl --fail --location --retry 2 --connect-timeout 15 --max-time 180 \
      -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl"; \
    curl --fail --location --retry 2 --connect-timeout 15 --max-time 30 \
      -o /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl.sha256"; \
    printf '%s  /usr/local/bin/kubectl\n' "$(cat /tmp/kubectl.sha256)" | sha256sum --check; \
    chmod 0755 /usr/local/bin/kubectl; \
    rm /tmp/kubectl.sha256; \
    kubectl version --client --output=json

# Keep the standalone scanner's dependencies separate from the application.
COPY backend/bootstrap.requirements.lock /app/bootstrap.requirements.lock
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --require-hashes -r /app/bootstrap.requirements.lock
COPY backend/semgrep.requirements.lock /app/semgrep.requirements.lock
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/semgrep && \
    /opt/semgrep/bin/python -m pip install --require-hashes -r /app/bootstrap.requirements.lock && \
    /opt/semgrep/bin/pip install --require-hashes --disable-pip-version-check --timeout 45 --retries 2 -r /app/semgrep.requirements.lock && \
    ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

# Python package auditing resolves wheels without installing target packages or
# executing repository build hooks. Its dependencies are isolated and pinned.
COPY backend/python-auditor.requirements.lock /app/python-auditor.requirements.lock
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/python-audit && \
    /opt/python-audit/bin/python -m pip install --require-hashes -r /app/bootstrap.requirements.lock && \
    /opt/python-audit/bin/python -m pip install --require-hashes -r /app/python-auditor.requirements.lock && \
    /opt/python-audit/bin/python -m pip_audit --version

# Release assets pinned to publisher-provided hashes; never execute an
# unversioned installer script or silently ship an incomplete scanner image.
RUN set -eu; arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch=x64; th_hash=dc24007c2f233bd61c05beabeb44aa27ea9b43288166279209abe0458c5ce76b; gl_hash=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;; \
      arm64) gl_arch=arm64; th_hash=7e65e771d2a247964056aa5edba0f8ae3945895e5dce867fe0ffbc7b0128239a; gl_hash=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;; \
      *) exit 1 ;; esac; \
    curl -sSfL --retry 2 --connect-timeout 15 --max-time 240 -o /tmp/th.tar.gz "https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.4/trufflehog_3.97.4_linux_${arch}.tar.gz"; \
    printf '%s  /tmp/th.tar.gz\n' "$th_hash" | sha256sum --check; \
    tar -xzf /tmp/th.tar.gz -C /usr/local/bin trufflehog; \
    curl -sSfL --retry 2 --connect-timeout 15 --max-time 120 -o /tmp/gl.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${gl_arch}.tar.gz"; \
    printf '%s  /tmp/gl.tar.gz\n' "$gl_hash" | sha256sum --check; \
    tar -xzf /tmp/gl.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/th.tar.gz /tmp/gl.tar.gz

COPY backend/requirements.txt /app/requirements.txt
COPY backend/requirements.lock /app/requirements.lock
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --require-hashes -r /app/requirements.lock

# Joern's large release archive is cached outside the image, including partial
# downloads. Resuming a bounded retry does not leave gigabytes in a final layer.
# The release extracts to joern-cli (the previous joern-cli-* glob never matched).
ENV JOERN_VERSION=2.0.392
RUN --mount=type=cache,target=/var/cache/lotus-downloads \
    set -eu; \
    archive="/var/cache/lotus-downloads/joern-${JOERN_VERSION}.zip"; \
    expected='ea1fcd24a2f8a9a0c45fd718e76fe0270aab638924336604ae7a4c111b230a2c822d9e52cc3348ff53f2d57bdec896fe314eb7e12ce4ea9ecfc1bacb6c10e4a5'; \
    attempt=1; verified=0; \
    while [ "$attempt" -le 3 ]; do \
      if unzip -tq "$archive" >/dev/null 2>&1; then \
        if printf '%s  %s\n' "$expected" "$archive" | sha512sum --check; then verified=1; break; fi; \
        rm -f "$archive"; \
      fi; \
      if curl -sSfL --connect-timeout 15 --max-time 600 --continue-at - \
           -o "$archive" "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-cli.zip"; then \
        if printf '%s  %s\n' "$expected" "$archive" | sha512sum --check; then verified=1; break; fi; \
        rm -f "$archive"; \
      fi; \
      attempt=$((attempt + 1)); \
    done; \
    if [ "$verified" -eq 1 ] \
       && unzip -q "$archive" -d /opt \
       && test -x /opt/joern-cli/joern; then \
      mv /opt/joern-cli /opt/joern; \
      ln -s /opt/joern/joern /usr/local/bin/joern; \
      ln -s /opt/joern/joern-parse /usr/local/bin/joern-parse; \
      ln -s /opt/joern/joern-export /usr/local/bin/joern-export; \
    else \
      rm -rf /opt/joern-cli; \
      echo "ERROR: Joern install failed; rerun the build to resume the cached download" >&2; \
      exit 1; \
    fi

COPY --from=lotus-go-tools /usr/local/go /usr/local/go
COPY --from=lotus-go-tools /opt/lotus-tools /opt/lotus-tools
ENV PATH=/usr/local/go/bin:/opt/lotus-tools:$PATH

COPY backend /app/backend
COPY frontend /app/frontend
COPY scripts/prewarm_audit_metadata.py /app/scripts/prewarm_audit_metadata.py
COPY README.md /app/README.md
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
COPY LICENSE /app/LICENSE

RUN chmod +x /app/docker-entrypoint.sh && chown -R lotus:lotus /app

ENV DATABASE_URL=postgresql://lotus:lotus@db:5432/lotus
ENV PYTHONPATH=/app
# Tool state must stay writable when the application root is read-only.
# The entrypoint creates these directories on the mounted data volume.
ENV HOME=/app/data/home \
    XDG_CACHE_HOME=/app/data/home/.cache \
    XDG_CONFIG_HOME=/app/data/home/.config \
    XDG_DATA_HOME=/app/data/home/.local/share

# Nginx: serve static frontend and proxy API requests to uvicorn, running as non-root lotus
RUN cat > /etc/nginx/nginx.conf <<'EOF'
user lotus;
worker_processes auto;
pid /tmp/nginx.pid;
error_log stderr;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /dev/stdout combined;
    client_body_temp_path /tmp;
    proxy_temp_path /tmp;
    fastcgi_temp_path /tmp;
    scgi_temp_path /tmp;
    uwsgi_temp_path /tmp;
    sendfile on;
    server {
        listen 8000;
        server_name _;
        root /app/frontend;
        index index.html;
        location / {
            try_files $uri /index.html;
        }
        location = /healthz { proxy_pass http://127.0.0.1:8001; }
        location = /readyz { proxy_pass http://127.0.0.1:8001; }
        location = /metrics { proxy_pass http://127.0.0.1:8001; }
        location /api/ {
            proxy_pass http://127.0.0.1:8001;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Connection "";
            proxy_buffering off;
            proxy_cache off;
            proxy_read_timeout 3600s;
        }
    }
}
EOF

# Supervisor: run gunicorn (uvicorn worker class) and nginx in one container as non-root lotus
RUN cat > /etc/supervisor/conf.d/lotus.conf <<'EOF'
[supervisord]
nodaemon=true
user=lotus
pidfile=/tmp/supervisord.pid
logfile=/tmp/supervisord.log
logfile_maxbytes=0
childlogdir=/tmp

[unix_http_server]
file=/tmp/supervisor.sock

[program:gunicorn]
command=/usr/local/bin/gunicorn backend.main:app -b 127.0.0.1:8001 -w 4 -k uvicorn.workers.UvicornWorker --access-logfile - --error-logfile - --preload
directory=/app
user=lotus
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:nginx]
command=/usr/sbin/nginx -g 'daemon off;'
user=lotus
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
EOF

USER lotus

EXPOSE 8000

CMD ["/app/docker-entrypoint.sh"]
