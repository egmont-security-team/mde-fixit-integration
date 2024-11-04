# The python version here does not acctually matter since it will
# be overriden by `uv` when creating a virtual environment.
FROM python:slim-bookworm

LABEL maintainer="daekjo@egmont.com" \
      description="MDE & Fix-It integration"

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY --from=ghcr.io/astral-sh/uv:0.4.28 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

RUN groupadd -r app-group && \
    useradd -r -g app-group -d /app -s /bin/bash app-user && \
    chown -R app-user:app-group /app

USER app-user

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev -v

COPY --chown=app-user:app-group . .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev -v

ENV PATH="/app/.venv/bin:$PATH"
