FROM golang:alpine as builder

WORKDIR /app

COPY . .

RUN go build -o fda .


FROM alpine:latest

LABEL maintainer="Junlong Zhang <hi@junlong.plus>"

WORKDIR /app

COPY --from=builder /app/fda .

EXPOSE 18080

ENTRYPOINT ["./fda"]