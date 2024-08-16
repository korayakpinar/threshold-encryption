FROM rust:slim

RUN useradd -ms /bin/sh user

WORKDIR /app

COPY lagrangehelpers /app/lagrangehelpers
COPY isvalidhelpers /app/isvalidhelpers
COPY target/release/examples/mempool /app/mempool

RUN chown -R user /app && \
    chmod +x /app/mempool

USER user

ENTRYPOINT ["/app/mempool"]
