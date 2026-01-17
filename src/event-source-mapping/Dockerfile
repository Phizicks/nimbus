
ARG VER=0.0.0

FROM python:3.13.11-trixie

RUN apt-get update && apt-get install -y curl unzip

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN mkdir -p /data

WORKDIR /app

COPY pyproject.toml /app/
RUN uv sync

COPY main.py custom_logger.py pyproject.toml timedlocking.py /app/

CMD ["uv", "run", "/app/main.py"]
