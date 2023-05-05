FROM rust:1.67

WORKDIR /usr/src/ddns-server
COPY . .

RUN cargo install --path .

CMD ["ddns-server"]