FROM python:3.12-slim

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.3

ENV POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

WORKDIR /workspace

# Copy only dependency manifests first so the layer is cached on code changes
COPY pyproject.toml ./

# Install dependencies (no root package yet – avoids re-install on every code change)
RUN poetry install --no-root

# Copy the rest of the project
COPY . .

# Install the project itself
RUN poetry install
