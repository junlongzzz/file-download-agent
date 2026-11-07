# File Download Agent

**file download agent server written in golang.**

## Features

- [x] Download file from url
- [x] Download file from local file
- [x] Serve WebDAV server

## Build

```shell
go build -o fda .
chmod +x fda
```

## Args and Env

| Argument       | Env               | Description                         | Default          |
|----------------|-------------------|-------------------------------------|------------------|
| -host          | FDA_HOST          | Server host                         | 0.0.0.0          |
| -port          | FDA_PORT          | Server port                         | 18080            |
| -sign-key      | FDA_SIGN_KEY      | Sign key for server                 | -                |
| -dir           | FDA_DIR           | Download file dir                   | files next to the executable |
| -webdav-enable | FDA_WEBDAV_ENABLE | Enable WebDAV server or not         | true             |
| -webdav-dir    | FDA_WEBDAV_DIR    | WebDAV root dir                     | same as dir      |
| -webdav-user   | FDA_WEBDAV_USER   | WebDAV username                     | anonymous        |
| -webdav-pass   | FDA_WEBDAV_PASS   | WebDAV password                     | sign-key, or a random password printed at startup |
| -forward-request-headers | FDA_FORWARD_REQUEST_HEADERS | Extra request headers to forward upstream (comma-separated) | none |
| -forward-response-headers | FDA_FORWARD_RESPONSE_HEADERS | Extra response headers to forward to the client (comma-separated) | none |
| -allow-private-network | FDA_ALLOW_PRIVATE_NETWORK | Allow private/loopback/link-local targets (disables SSRF protection) | false |
| -auth-max-failures | FDA_AUTH_MAX_FAILURES | Max failed auth attempts per client per window | 10 |
| -auth-failure-window | FDA_AUTH_FAILURE_WINDOW | Auth failure rate-limit window | 1m |
| -log-level     | FDA_LOG_LEVEL     | Log level: debug, info, warn, error | info             |
| -cert-file     | FDA_CERT_FILE     | SSL cert file path                  | -                |
| -cert-key-file | FDA_CERT_KEY_FILE | SSL cert key file path              | -                |
| -help, -h      | -                 | Show help                           | -                |
| -version       | -                 | Show version                        | -                |

> args has higher priority than env

> [!IMPORTANT]
> It is strongly recommended to specify a random `sign-key` of at least 16 characters in
> production. Failed signature checks are rate-limited per client, but a strong key remains the
> primary protection against online guessing. Serve the UI over HTTPS when it is exposed.
>
> Failed-auth rate limiting keys on the client IP taken from `X-Forwarded-For` (first entry) or
> `X-Real-IP`. If the service is exposed directly to the Internet, clients can spoof these
> headers and bypass the limit. Deploy behind a trusted reverse proxy that overwrites them.

## Run

- Show usage

```shell
./fda -h
```

- Args

```shell
./fda -host=127.0.0.1 -port=18080 -sign-key=<your_sign_key> -dir=./files
```

- Env

```shell
export FDA_HOST=127.0.0.1
export FDA_PORT=18080
export FDA_SIGN_KEY=<your_sign_key>
export FDA_DIR=./files
./fda
```

- Proxy

```shell
export HTTP_PROXY=http://<your_proxy_host>:<your_proxy_port>
export HTTPS_PROXY=http://<your_proxy_host>:<your_proxy_port>
./fda
```

- Use [Task](https://taskfile.dev)

```shell
task run
```

## Docker

```shell
docker run -d --name file-download-agent -p 18080:18080 -e FDA_PORT=18080 junlongzzz/file-download-agent
```

## Docker Compose

```yaml
services:
  file-download-agent:
    image: junlongzzz/file-download-agent
    container_name: file-download-agent
    restart: always
    ports:
      - "18080:18080"
    volumes:
      - ./files:/app/files
    environment:
      - FDA_PORT=18080
      - FDA_SIGN_KEY=<your_sign_key>
```

## Usage

```text
http://127.0.0.1:18080
http://127.0.0.1:18080/download
http://127.0.0.1:18080/webdav/
```
