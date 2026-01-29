FROM scylladb/scylla:latest

# Enable CDC and Alternator Streams via config files
RUN mkdir -p /etc/scylla/conf.d && \
    echo "enable_cdc: true" > /etc/scylla/conf.d/cdc.yaml && \
    echo "cdc_space: system_distributed" >> /etc/scylla/conf.d/cdc.yaml && \
    echo "cdc_enable_logging: true" >> /etc/scylla/conf.d/cdc.yaml && \
    echo "alternator_streams_time_window_s: 3600" >> /etc/scylla/conf.d/alternator_streams.yaml && \
    echo "enable_alternator_streams: true" >> /etc/scylla/conf.d/alternator_streams.yaml && \
    echo "tablets_mode_for_new_keyspaces: disabled" >> /etc/scylla/conf.d/tablets.yaml

USER scylla

EXPOSE 8000

# Enable experimental Alternator Streams feature
CMD [ "--experimental-features=alternator-streams", \
        "--alternator-write-isolation=always", \
        "--alternator-address=0.0.0.0", \
        "--alternator-port=8000" \
    ]
