FROM --platform=linux/amd64 ghcr.io/cargo-lambda/cargo-lambda:latest AS build

WORKDIR /build
COPY . .

# Set RUSTFLAGS for maximum compatibility - no modern CPU features
# target-feature=-crt-static links glibc dynamically for better compatibility
ENV RUSTFLAGS="-C target-cpu=x86-64 -C target-feature=-crt-static"

# Build with explicit architecture and compiler target
RUN cargo lambda build --release --target x86_64-unknown-linux-gnu

# Debug: verify binary details
RUN file /build/target/lambda/*/bootstrap && \
    ldd /build/target/lambda/*/bootstrap || echo "Static binary"

FROM --platform=linux/amd64 public.ecr.aws/lambda/provided:al2023 AS runtime

# Copy the bootstrap binary
COPY --from=build /build/target/lambda/*/bootstrap /var/runtime/bootstrap

ENTRYPOINT [ "/var/runtime/bootstrap" ]
