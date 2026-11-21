#!/bin/bash
set -e

if [ -n "${BAZ_HOST_UID:-}" ] && [ "${BAZ_HOST_UID}" != "0" ] && [ "${BAZ_HOST_UID}" != "$(id -u)" ]; then
  exec sudo -E -- bash -c '
    set -e
    gid="${BAZ_HOST_GID:-$BAZ_HOST_UID}"
    old_uid="$1"
    old_gid="$2"
    export PATH="$3"
    shift 3
    sed -i "s|^pentester:x:${old_uid}:${old_gid}:|pentester:x:${BAZ_HOST_UID}:${gid}:|" /etc/passwd
    sed -i "s|^pentester:x:${old_gid}:|pentester:x:${gid}:|" /etc/group
    chown -R "${BAZ_HOST_UID}:${gid}" /home/pentester /app/certs
    chown "${BAZ_HOST_UID}:${gid}" /workspace
    exec setpriv --reuid "${BAZ_HOST_UID}" --regid "${gid}" --init-groups "$0" "$@"
  ' "$0" "$(id -u)" "$(id -g)" "$PATH" "$@"
fi

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi

# Caido enforces a Host allowlist (DNS-rebinding protection) and rejects requests
# whose Host header is a hostname it doesn't recognize. To reach Caido over a
# hostname (rather than an IP literal), set BAZ_CAIDO_ALLOWED_DOMAINS to a
# comma-separated list of hostnames to allow. Unset by default.
# See https://docs.caido.io/app/guides/domain_allowlist
CAIDO_UI_DOMAIN_ARGS=()
if [ -n "${BAZ_CAIDO_ALLOWED_DOMAINS:-}" ]; then
  IFS=',' read -ra _caido_domains <<< "${BAZ_CAIDO_ALLOWED_DOMAINS}"
  for _d in "${_caido_domains[@]}"; do
    [ -n "$_d" ] && CAIDO_UI_DOMAIN_ARGS+=(--ui-domain "$_d")
  done
fi

# Install the CLI on first use when the image build could not fetch it (the
# build network cannot always reach caido.download, though a running container
# can). One retry loop, then a clear failure — a scan without a proxy is not a
# scan, so this must not fail silently.
if ! command -v caido-cli >/dev/null 2>&1; then
  echo "caido-cli missing; fetching from api.caido.io ..."
  # The proxy env is set for the scan, pointing at Caido itself. Downloading the
  # Caido CLI through the not-yet-started Caido is a deadlock: verified failure
  # is `curl: (7) Failed to connect ... over proxy 127.0.0.1`. Bypass the proxy
  # for this download only.
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
  _caido_version=$(curl -fsSL --retry 3 --connect-timeout 20 \
      https://api.caido.io/releases/latest 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' 2>/dev/null) || true
  if [ -n "${_caido_version:-}" ]; then
    _caido_url="https://caido.download/releases/v${_caido_version}/caido-cli-v${_caido_version}-linux-x86_64.tar.gz"
    if curl -fsSL --retry 5 --retry-delay 3 --connect-timeout 20 -o /tmp/caido.tgz "$_caido_url"; then
      tar -xzf /tmp/caido.tgz -C /tmp && chmod +x /tmp/caido-cli && \
        sudo mv /tmp/caido-cli /usr/local/bin/ && rm -f /tmp/caido.tgz && \
        echo "caido-cli v${_caido_version} installed"
    fi
  fi
fi
# Do NOT exit if the CLI is missing. Exiting kills the container before the scan
# starts, which surfaces as an opaque "exec transport error" from the SDK.
# Warn loudly, then start without the proxy: the scan remains usable for targets
# that do not need interception.
if ! command -v caido-cli >/dev/null 2>&1; then
  echo "ERROR: caido-cli unavailable; starting without the Caido proxy. HTTP" >&2
  echo "traffic will not be captured or intercepted, so evidence will be incomplete." >&2
  exec "$@"
fi

caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          "${CAIDO_UI_DOMAIN_ARGS[@]}" \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!
echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"

echo "Waiting for Caido API to be ready..."
CAIDO_READY=false
for i in {1..30}; do
  if ! kill -0 $CAIDO_PID 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API (iteration $i)."
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  if curl -s -o /dev/null -w "%{http_code}" http://localhost:${CAIDO_PORT}/graphql/ | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi
  sleep 1
done

if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status: $(kill -0 $CAIDO_PID 2>&1 && echo 'running' || echo 'dead')"
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

sleep 2

echo "Caido is up — host bootstraps the guest token + project via the Python SDK."

echo "Configuring system-wide proxy settings..."

cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=http://127.0.0.1:${CAIDO_PORT}
export https_proxy=http://127.0.0.1:${CAIDO_PORT}
export HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
export HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
export ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
export NO_PROXY=localhost,127.0.0.1
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
NO_PROXY=localhost,127.0.0.1
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
EOF

# Use POSIX `.` (not the bashism `source`) so these lines are safe when the rc
# files are read by a POSIX shell (e.g. `sh -lc`), which otherwise fails with
# "source: not found". `.` is understood by bash, zsh, and dash alike.
echo ". /etc/profile.d/proxy.sh" >> ~/.bashrc
echo ". /etc/profile.d/proxy.sh" >> ~/.zshrc

. /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
sudo -u pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
sudo -u pentester certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
echo "✅ CA added to browser trust store"

mkdir -p /workspace/.agent-browser-screenshots

# The browser DevTools MCP gateway is NOT started here. baz/browser/stack.py
# owns it and starts it on every scan (connect() -> start_in_sandbox()), which
# is where it can be restarted with the correct flags and released cleanly
# before a restart. Starting a second copy in this entrypoint only guaranteed
# a port collision on 48081: this script runs as root, so the later
# `fuser -k 48081/tcp` from the non-root pentester exec session could not
# release the root-owned listener, and the real gateway died with EADDRINUSE.
echo "✅ Container ready"

cd /workspace
exec "$@"
