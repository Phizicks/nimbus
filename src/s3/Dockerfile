FROM minio/minio:latest

ENV MINIO_ROOT_USER=localcloud
ENV MINIO_ROOT_PASSWORD=localcloud

# Copy a script to configure webhooks at container startup
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Override the default entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
