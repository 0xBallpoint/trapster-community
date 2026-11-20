# ============================================
# Stage 1: locked Python dependencies
# ============================================
FROM python:3.11-slim AS python-deps

# uv is only used here: the final image gets /venv, not uv
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv

WORKDIR /lock

# Dependencies from uv.lock, checked against their sha256 hashes.
# --locked: fail if uv.lock is out of date. --no-build: wheels only.
COPY pyproject.toml uv.lock ./
RUN UV_PROJECT_ENVIRONMENT=/venv UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 UV_NO_CACHE=1 \
    uv sync --locked --no-build --no-install-project

# ============================================
# Stage 2: final image
# ============================================
FROM python:3.11-slim

COPY --from=python-deps /venv /venv
ENV PATH="/venv/bin:$PATH"

WORKDIR /app

# Create configuration directory
RUN mkdir -p /etc/trapster

# Copy application code - these are likely to change more frequently
# so we place them after the dependency installation
COPY trapster/data/trapster.conf /etc/trapster/trapster.conf
COPY main.py /app/
COPY trapster /app/trapster/

# Run main.py when the container launches
ENTRYPOINT ["python3", "main.py", "-c", "/etc/trapster/trapster.conf"]
