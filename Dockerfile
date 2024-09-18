FROM rust:alpine as builder

WORKDIR /usr/src/tored
COPY . .

RUN apk add --no-cache -U musl-dev openssl-dev
ENV OPENSSL_DIR=/usr
RUN cargo build --release

FROM alpine:latest

COPY --from=builder /usr/src/tored/target/release/tored /usr/local/bin/tored/tored

WORKDIR /usr/local/bin/tored
CMD ["./tored"]
