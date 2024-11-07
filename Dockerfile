FROM mcr.microsoft.com/azure-functions/python:4-python3.11
WORKDIR /home/site/wwwroot

LABEL maintainer="daekjo@egmont.com" \
      description="MDE & Fix-It integration"

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true

ENV PYTHONUNBUFFERED=1

COPY --from=ghcr.io/astral-sh/uv:0.4.28 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev -v

COPY . .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev -v

ENV PATH="/home/site/wwwroot/.venv/bin:$PATH"
