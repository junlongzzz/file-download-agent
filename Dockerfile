FROM golang:alpine AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o fda


FROM alpine:latest

LABEL maintainer="Junlong Zhang <hi@junlong.plus>"

ENV TZ=Asia/Shanghai

WORKDIR /app

COPY --from=builder /app/fda .

EXPOSE 18080

ENTRYPOINT ["./fda"]