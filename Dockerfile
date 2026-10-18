# SPDX-License-Identifier: AGPL-3.0-only
# ExecBound runtime image: gateway or protected mock provider, chosen by the command.
# Built only from the locked environment; configuration and secrets arrive at runtime.
# Base images are pinned by digest.

# The console is built first, in a Node stage that ends here: the runtime image below never
# carries Node, a package manager or node_modules, only the files Vite wrote. pnpm comes from
# corepack at the exact version and hash package.json names; the lockfile is frozen and no
# dependency runs an install script (console/pnpm-workspace.yaml).
FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS console

RUN corepack enable
WORKDIR /console
COPY console/package.json console/pnpm-lock.yaml console/pnpm-workspace.yaml ./
# Dependencies first so a source change does not invalidate this layer.
RUN pnpm install --frozen-lockfile
COPY console/ ./
# The committed Tines stories and their licence, which the build copies unchanged for Getting
# started's downloads (console/scripts/stories.ts reads ../integrations/ from here).
COPY integrations/tines/execbound-governed-action.json integrations/tines/execbound-gate.json /integrations/tines/
COPY integrations/LICENSE /integrations/LICENSE
# The console edition this image carries: `core` unless the build names another with
# `--build-arg CONSOLE_EDITION=<edition>`, which must be one package.json has a
# `build:<edition>` script for, or the build fails. Every edition is written into
# ../src/execbound/surfaces/console_dist relative to the console, where the package reads it.
ARG CONSOLE_EDITION=core
RUN mkdir -p /src/execbound/surfaces && \
    if [ "$CONSOLE_EDITION" = core ]; then pnpm build; \
    else CONSOLE_OUT_DIR=../src/execbound/surfaces/console_dist pnpm run "build:$CONSOLE_EDITION"; fi


FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.13@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6 /uv /bin/uv

ENV UV_PROJECT_ENVIRONMENT=/opt/execbound \
    UV_PYTHON=/usr/local/bin/python3.13 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

WORKDIR /build
COPY pyproject.toml uv.lock ./
# The client package is installed from the `showcase` group, with its MCP extra, so the image
# carries `execbound-demo` and an agent-side client; the gateway never imports it.
COPY clients/python/pyproject.toml clients/python/README.md clients/python/LICENSE clients/python/
COPY clients/python/src clients/python/src
# Locked sync validates local development sources even when --no-dev excludes installation.
# Keep this producer in the builder only; it is never a gateway runtime dependency.
COPY integrations/mde-producer/pyproject.toml integrations/mde-producer/README.md integrations/mde-producer/LICENSE integrations/mde-producer/
COPY integrations/mde-producer/src integrations/mde-producer/src
# The provider protocol and the connectors are runtime dependencies of the server:
# Apache-2.0 packages beside it, installed from the locked path sources.
COPY protocol/pyproject.toml protocol/README.md protocol/LICENSE protocol/
COPY protocol/src protocol/src
COPY connectors/pyproject.toml connectors/README.md connectors/LICENSE connectors/
COPY connectors/src connectors/src
# Runtime dependencies first so source changes do not invalidate this layer.
RUN uv sync --locked --no-dev --group showcase --no-install-project --no-editable
# The licence texts the server's metadata names (`license-files`), so its installed dist-info
# carries them; a package built without them carries none.
COPY LICENSE THIRD_PARTY_NOTICES.md ./
COPY src ./src
# The console build joins the package before it is installed, so the wheel carries it.
COPY --from=console /src/execbound/surfaces/console_dist ./src/execbound/surfaces/console_dist
RUN uv sync --locked --no-dev --group showcase --no-editable


FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641

# Installation happens in the builder. The running service needs neither pip (including
# its vendored msgpack/setuptools) nor ensurepip's bundled installer wheel. Remove both
# instead of carrying unrelated installer advisories into the runtime image.
RUN python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && python -c "import importlib.util; assert all(importlib.util.find_spec(name) is None for name in ('pip', 'ensurepip'))"

# A login shell and an empty ~/.ssh let a hosting platform's operator shell open a session as
# this non-root user. The image runs no SSH server of its own.
RUN groupadd --gid 10001 execbound \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/sh execbound \
    && install -d -m 0700 -o execbound -g execbound /home/execbound/.ssh

COPY --from=builder /opt/execbound /opt/execbound
WORKDIR /srv/execbound
# Migrations are applied from this image with the owner connection; they are not
# part of the wheel, so they travel alongside it.
COPY alembic.ini ./
COPY migrations ./migrations

# The source commit the image was built from, reported by /health/ready so a trial record
# can cite what it talked to; empty when the build did not state it.
ARG EXECBOUND_COMMIT=""
ENV PATH=/opt/execbound/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EXECBOUND_COMMIT=$EXECBOUND_COMMIT

USER execbound
EXPOSE 8000

# Every process serves port 8000 inside its own container, so one TCP check fits the
# gateway and both providers. Orchestrators should probe the gateway's /health/ready.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 3).close()"]

CMD ["uvicorn", "execbound.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-level", "error"]
