FROM golang:alpine AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -v -o fda


FROM alpine:latest

LABEL maintainer="Junlong Zhang <hi@junlong.plus>"

WORKDIR /app

COPY --from=builder /app/fda .

EXPOSE 18080

ENTRYPOINT ["./fda"]