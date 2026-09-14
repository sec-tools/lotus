#!/bin/sh
# Lotus container entrypoint: honour WEB_CONCURRENCY / LOTUS_DEPLOY_PROFILE for gunicorn.
set -eu

# Tool settings, caches, and user-level runtimes must work with a read-only
# image filesystem. Dockerfile defaults point HOME/XDG at the writable data
# volume; explicit deployment overrides remain authoritative.
umask 077
HOME="${HOME:-${LOTUS_DATA_DIR:-/app/data}/home}"
XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
export HOME XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME
for LOTUS_RUNTIME_PATH in "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"; do
  case "$LOTUS_RUNTIME_PATH" in
    /*) ;;
    *) printf 'Lotus runtime directory must be absolute: %s\n' "$LOTUS_RUNTIME_PATH" >&2; exit 1 ;;
  esac
  if ! mkdir -p "$LOTUS_RUNTIME_PATH"; then
    printf 'Cannot create Lotus runtime directory %s; mount a writable data volume or configure HOME/XDG paths.\n' "$LOTUS_RUNTIME_PATH" >&2
    exit 1
  fi
  if ! LOTUS_RUNTIME_CHECK=$(mktemp "$LOTUS_RUNTIME_PATH/.lotus-write-check.XXXXXX"); then
    printf 'Lotus runtime directory is not writable: %s; check data-volume ownership and HOME/XDG configuration.\n' "$LOTUS_RUNTIME_PATH" >&2
    exit 1
  fi
  rm -f "$LOTUS_RUNTIME_CHECK"
done
unset LOTUS_RUNTIME_PATH LOTUS_RUNTIME_CHECK

WORKERS="${WEB_CONCURRENCY:-${LOTUS_GUNICORN_WORKERS:-4}}"
PROFILE="${LOTUS_DEPLOY_PROFILE:-single}"
case "$PROFILE" in
  single|solo|local|dev) WORKERS=1 ;;
esac

CONF="/tmp/lotus-supervisord.conf"
cat > "$CONF" <<EOF
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
command=/usr/local/bin/gunicorn backend.main:app -b 127.0.0.1:8001 -w ${WORKERS} -k uvicorn.workers.UvicornWorker --access-logfile - --error-logfile - --timeout 600 --graceful-timeout 30
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

exec /usr/bin/supervisord -c "$CONF"
