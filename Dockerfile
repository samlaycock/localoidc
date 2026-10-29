# syntax=docker/dockerfile:1

FROM rust:1.99-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY assets assets
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin localoidc \
    && cp target/release/localoidc /usr/local/bin/localoidc
RUN mkdir /data

# Run: distroless as a non-root user. State (signing keys, SQLite) lives in /data.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /usr/local/bin/localoidc /usr/local/bin/localoidc
COPY --from=build --chown=nonroot:nonroot /data /data
ENV LOCALOIDC_HOST=0.0.0.0 \
    LOCALOIDC_DATA_DIR=/data
VOLUME /data
EXPOSE 9400
ENTRYPOINT ["/usr/local/bin/localoidc"]
