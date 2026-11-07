#!/bin/sh
set -eu
: "${BROWSERD_RELEASE_ROOT:?immutable release root is required}"
: "${BROWSERD_SANDBOX_SECCOMP_FILTER:?qualified binary seccomp filter is required}"
# FD 3/4 belong to Chromium CDP. Open the operator-qualified filter on a different inherited FD.
exec 5< "$BROWSERD_SANDBOX_SECCOMP_FILTER"
export BROWSERD_SANDBOX_SECCOMP_FD=5
exec "$BROWSERD_RELEASE_ROOT/bin/browser-sandboxd"
