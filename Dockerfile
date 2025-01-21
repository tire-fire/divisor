FROM golang:1.23-alpine as builder

RUN apk add --no-cache build-base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o divisor .

FROM alpine:3.20
RUN apk add --no-cache \
    iproute2 \
    iptables \
    bash

WORKDIR /app
COPY --from=builder /app/divisor /app/divisor
COPY .env /app/.env

ENTRYPOINT ["/app/divisor"]
