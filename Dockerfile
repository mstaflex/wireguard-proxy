# --- build stage ---
FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir poetry==1.8.3

ENV POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

WORKDIR /app

COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --only main --no-root

COPY src/ src/
RUN poetry build --format wheel && \
    .venv/bin/pip install --no-deps dist/*.whl


# --- runtime stage ---
FROM python:3.12-slim AS runtime

# Non-root user for least-privilege operation
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Bring in only the virtual-env from the builder (no Poetry, no build tools)
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH"

# UDP ports (both must be published with -p host:container/udp)
EXPOSE 51820/udp 51821/udp

USER appuser

ENTRYPOINT ["/app/.venv/bin/wireguard-proxy"]
CMD ["--server-port", "51820", "--client-port", "51821", "--log-level", "INFO"]
