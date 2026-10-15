# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений

# Loona: the web UI, the job worker, Ansible and OpenTofu in one image.
#
#   docker compose up -d --build        see compose.yaml
#
# Build arguments:
#   TOFU_VERSION     OpenTofu release to bundle.
#   ANSIBLE_PACKAGE  "ansible" (default) brings the community collections -
#                    about 10 000 modules for the editor; "ansible-core" makes
#                    a much smaller image with ansible.builtin only.
FROM python:3.12-slim-bookworm

ARG TOFU_VERSION=1.12.6
ARG ANSIBLE_PACKAGE=ansible

# Follows core/version.py; core.tests checks the two agree.
LABEL org.opencontainers.image.title="Loona" \
      org.opencontainers.image.description="Ansible and OpenTofu with a web interface" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/var/lib/loona \
    LOONA_DATA_DIR=/var/lib/loona/jobs \
    LOONA_KEYS_DIR=/var/lib/loona/keys \
    LOONA_DEBUG=false \
    LOONA_RUNNER_MODE=celery \
    GIT_ALLOW_PROTOCOL=https:http:ssh:git

# git for OpenTofu projects kept in a repository; ssh and sshpass for Ansible.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

# OpenTofu from its official release, checked against the published checksums.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    base="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"; \
    archive="tofu_${TOFU_VERSION}_linux_${arch}.tar.gz"; \
    cd /tmp; \
    curl -fsSLO "${base}/${archive}"; \
    curl -fsSLO "${base}/tofu_${TOFU_VERSION}_SHA256SUMS"; \
    grep " ${archive}\$" "tofu_${TOFU_VERSION}_SHA256SUMS" | sha256sum -c -; \
    tar -xzf "${archive}" -C /usr/local/bin tofu; \
    rm -f /tmp/tofu_*; \
    tofu version

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt "${ANSIBLE_PACKAGE}"

COPY . .
RUN LOONA_SECRET_KEY=build-only python manage.py collectstatic --noinput \
 && useradd --system --uid 1000 --home-dir /var/lib/loona --shell /usr/sbin/nologin loona \
 && mkdir -p /var/lib/loona \
 && chown loona:loona /var/lib/loona

USER loona
VOLUME /var/lib/loona
EXPOSE 8000
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]
