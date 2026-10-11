# syntax=docker/dockerfile:1
FROM python:3.13-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md requirements.lock ./
COPY src/ ./src/
COPY config/ ./config/

RUN python -m pip wheel --wheel-dir /wheels -r requirements.lock .

FROM python:3.13-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
    && apt-get install --no-install-recommends -y libpq5 tar tini zstd \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

COPY --from=builder /wheels /wheels
RUN /opt/venv/bin/python -m pip install --no-index --find-links=/wheels threattrace==0.1.0 \
    && rm -rf /wheels

RUN groupadd --gid 10001 threattrace \
    && useradd --uid 10001 --gid threattrace --create-home --home-dir /home/threattrace --shell /usr/sbin/nologin threattrace \
    && mkdir -p /app /var/lib/threattrace \
    && chown -R threattrace:threattrace /app /var/lib/threattrace

WORKDIR /app
USER threattrace

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["threattrace", "--help"]
