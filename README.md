# File Download Agent

**file download agent server written in golang.**

## Compile

```shell
go build -o fda .
```

## Run

### Command

```shell
chmod +x fda
./fda --port=18080 --sign-key=<your_sign_key>
```

```shell
export FDA_PORT=18080
export FDA_SIGN_KEY=<your_sign_key>
chmod +x fda
./fda
```

### Docker

```shell
docker run -d --name file-download-agent -p 18080:18080 -e FDA_PORT=18080 junlongzzz/file-download-agent
```

### Docker Compose

```yaml
services:
  file-download-agent:
    image: junlongzzz/file-download-agent
    container_name: file-download-agent
    restart: always
    ports:
      - 18080:18080
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    environment:
      - FDA_PORT=18080
      - FDA_SIGN_KEY=<your-sign-key>
```

## Usage

```text
visit http://localhost:18080
```
