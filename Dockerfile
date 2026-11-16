# Tripwire in a container. Default command: the one-minute demo, which needs no network at all:
#   docker build -t tripwire .
#   docker run --rm --network none tripwire
# See docs/DOCKER.md for running against a model on your machine.
FROM python:3.12-slim

# uv, pinned, installs exactly what uv.lock says (same versions the tests ran with)
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
# dependencies first, so editing source does not reinstall them
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY lab ./lab
RUN uv sync --frozen --no-dev

# never run as root; results go to /app/out (mount a folder there to keep them)
RUN useradd --create-home --uid 10001 tripwire && mkdir -p /app/out && chown tripwire /app/out
USER tripwire
VOLUME ["/app/out"]

ENTRYPOINT ["tripwire"]
CMD ["demo"]
