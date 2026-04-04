# --- build stage ---
FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir poetry==1.8.3

ENV POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN poetry install --only main --no-root

COPY src/ src/
RUN poetry install --only main


# --- runtime stage ---
FROM python:3.12-slim AS runtime

# Non-root user for least-privilege operation
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Bring in only the virtual-env from the builder (no Poetry, no build tools)
COPY --from=builder /app/.venv /app/.venv

# Copy the installed package
COPY --from=builder /app/src /app/src

ENV PATH="/app/.venv/bin:$PATH"

# UDP ports (both must be published with -p host:container/udp)
EXPOSE 51820/udp 51821/udp

USER appuser

ENTRYPOINT ["/app/.venv/bin/wireguard-proxy"]
CMD ["--server-port", "51820", "--client-port", "51821", "--log-level", "INFO"]
