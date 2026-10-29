FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:stable-slim
COPY --from=build /src/target/release/localoidc /usr/local/bin/localoidc
ENV LOCALOIDC_HOST=0.0.0.0 LOCALOIDC_DATA_DIR=/data
VOLUME /data
EXPOSE 9400
ENTRYPOINT ["localoidc"]
