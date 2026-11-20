#!/bin/sh
# Regenerates uv.lock (exact versions + hashes) from pyproject.toml.
# UPGRADE=all bumps every package, UPGRADE=<name> only that one.
# Same uv version as the Dockerfile and CI.
set -e

cd "$(dirname "$0")/.."

UV_VERSION=0.13.9

case "${UPGRADE:-}" in
    "") set -- ;;
    all) set -- --upgrade ;;
    *) set -- --upgrade-package "$UPGRADE" ;;
esac

echo "==> Locking uv.lock with uv $UV_VERSION..."
uv tool run --from "uv==$UV_VERSION" uv lock "$@"
