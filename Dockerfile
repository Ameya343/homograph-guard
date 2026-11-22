# syntax=docker/dockerfile:1
#
# Hardened runtime for homograph-guard.
#   docker build -t homograph-guard .
# Always start it through sandbox/run.sh (Linux/macOS) or sandbox/run.ps1 (Windows),
# or through the GUI - they add the lock-down flags (read-only, no capabilities, ...).
#
# For reproducible builds, pin the base image by digest:
#   FROM python:3.15-slim@sha256:<digest from `docker buildx imagetools inspect python:3.15-slim`>
FROM python:3.15-slim

LABEL org.opencontainers.image.title="homograph-guard" \
      org.opencontainers.image.description="IDN homograph phishing checker with multi-resolver DNS comparison" \
      org.opencontainers.image.source="https://github.com/Ameya343/homograph-guard" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.lock ./
# Hash-pinned wheels only; then remove pip so the runtime has no package manager.
RUN pip install --require-hashes --only-binary=:all: --no-deps -r requirements.lock \
 && python -m pip uninstall -y pip \
 && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin hguard

COPY src/ /app/src/

USER 10001:10001
# -I: isolated mode (ignores PYTHON* environment variables, user site-packages and the CWD)
# -B: never write bytecode
ENTRYPOINT ["python", "-I", "-B", "/app/src/homograph_guard/_entry.py"]
CMD ["--help"]
