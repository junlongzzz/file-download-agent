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

| Argument       | Env               | Description                         | Default       |
|----------------|-------------------|-------------------------------------|---------------|
| -host          | FDA_HOST          | Server host                         | 0.0.0.0       |
| -port          | FDA_PORT          | Server port                         | 18080         |
| -sign-key      | FDA_SIGN_KEY      | Sign key for server                 | -             |
| -dir           | FDA_DIR           | Download file dir                   | ./files       |
| -webdav-dir    | FDA_WEBDAV_DIR    | WebDAV root dir                     | same as dir   |
| -webdav-user   | FDA_WEBDAV_USER   | WebDAV username                     | anonymous     |
| -webdav-pass   | FDA_WEBDAV_PASS   | WebDAV password                     | md5(sign_key) |
| -log-level     | FDA_LOG_LEVEL     | Log level: debug, info, warn, error | info          |
| -cert-file     | FDA_CERT_FILE     | SSL cert file path                  | -             |
| -cert-key-file | FDA_CERT_KEY_FILE | SSL cert key file path              | -             |
| -help, -h      | -                 | Show help                           | -             |
| -version       | -                 | Show version                        | -             |

> args has higher priority than env

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
      - 18080:18080
    volumes:
      - ./files:/app/files
    environment:
      - FDA_PORT=18080
      - FDA_SIGN_KEY=<your_sign_key>
```

## Usage

```text
http://localhost:18080
http://localhost:18080/download
http://localhost:18080/webdav/
```
