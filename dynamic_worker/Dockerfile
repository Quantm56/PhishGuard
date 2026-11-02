# PhishGuard Dynamic-Scan Worker
# ================================
# Multi-stage build so the final image does not contain build tools.
#
# Security decisions
# ------------------
# * Base: mcr.microsoft.com/playwright/python – maintained image with Chromium already
#   bundled and its dependencies pre-installed.
# * Non-root runtime user (pwuser, uid 1001). The entrypoint.sh runs as root briefly
#   to set up iptables rules, then drops to pwuser via gosu / exec.
# * NET_ADMIN capability is granted via docker-compose (not baked into the image).
# * No host directories are mounted into the container.
# * No application API keys or .env file is passed in.
# * The container is ephemeral: --rm is set in PhishGuard's docker-compose.yml.

FROM python:3.12-slim

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        gosu \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────────
COPY requirements_worker.txt /tmp/requirements_worker.txt
RUN pip install --no-cache-dir -r /tmp/requirements_worker.txt

# ── Set shared browser path so non-root pwuser can access it ──────────────────
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# ── Install Chromium and its shared library dependencies only ─────────────────
RUN playwright install --with-deps chromium && chmod -R 755 /ms-playwright

# ── Ensure non-root runtime user pwuser exists ───────────────────────────────
RUN id -u pwuser >/dev/null 2>&1 || (groupadd -g 1001 pwuser && useradd -u 1001 -g pwuser -m -s /bin/bash pwuser)

# ── Copy worker sources ────────────────────────────────────────────────────────
WORKDIR /app
COPY worker.py        /app/worker.py
COPY entrypoint.sh    /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# ── Drop to non-root for the actual worker process ─────────────────────────────
# entrypoint.sh runs as root to set iptables, then execs the worker as pwuser
# via gosu. The CMD is the actual worker invocation.
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gosu", "pwuser", "python", "/app/worker.py"]

