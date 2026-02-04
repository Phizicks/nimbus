
ARG VER=0.0.0

FROM python:3.13.11-trixie

RUN apt-get update && apt-get install -y curl unzip

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY *.py pyproject.toml /app/

WORKDIR /app
RUN uv sync

CMD ["uv", "run", "/app/main.py"]
