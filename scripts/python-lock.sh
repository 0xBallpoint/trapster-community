#!/bin/sh
# Regenerates uv.lock from pyproject.toml.
#
# Every package, transitive ones included, gets an exact version and the
# sha256 hashes of its files. The Docker image and CI install with
# `uv sync --locked`, which checks every file against those hashes.
#
# Only versions published at least 7 days ago are accepted (exclude-newer in
# pyproject.toml, which also explains the exception for an urgent fix).
#
# UPGRADE=all bumps every package, UPGRADE=<name> only that one. Without it,
# versions already in uv.lock are kept.
#
# Uses the same uv version as the Dockerfile, CI and Renovate (constraints.uv
# in renovate.json5), so the lock format is one they all accept.
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
