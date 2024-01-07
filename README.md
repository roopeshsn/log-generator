# Log Generator

Generate apache style access log and secure entries using non-routable IP addresses. Useful for generating example data for testing log analysis tools like ELK, Splunk, etc.

## Docker

Build the image,

```
docker build -t log-generator .
```

Spin up a container,

```
docker run -v ${PWD}:/app -h web -d log-generator 
```

## Docker Compose

```
docker compose up -d

docker compose down
```

Run another container to speed up the generation of logs.