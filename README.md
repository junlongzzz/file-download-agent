# File Download Agent

**file download agent server written in golang.**

## Compile

```shell
go build -o fda .
chmod +x fda
```

## Run

- Show usage

```shell
./fda -h
```

- Args

```shell
./fda --host=127.0.0.1 --port=18080 --sign-key=<your_sign_key>
```

- Env

```shell
export FDA_HOST=127.0.0.1
export FDA_PORT=18080
export FDA_SIGN_KEY=<your_sign_key>
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
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    environment:
      - FDA_PORT=18080
      - FDA_SIGN_KEY=<your-sign-key>
```

## Usage

```text
http://localhost:18080
http://localhost:18080/download
http://localhost:18080/webdav
```
