
ARG VER=0.0.0

FROM python:3.13.11-trixie

RUN apt-get update && apt-get install -y curl unzip

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY main.py log_manager.py timedlocking.py custom_logger.py pyproject.toml /app/

# Should move to S3 for ZIPs and ECR for runtime specific builds rather than rebuild every time.
RUN mkdir -p /data/lambda-files

WORKDIR /app
RUN uv sync

CMD ["uv", "run", "/app/main.py"]
