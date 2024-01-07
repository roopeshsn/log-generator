FROM ubuntu:22.04

RUN apt update && apt install -y python3 curl wget

WORKDIR /app

COPY . .

CMD ["python3", "log_generator.py"]
