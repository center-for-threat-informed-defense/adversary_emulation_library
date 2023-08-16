FROM ubuntu:20.04
RUN apt-get update -y && apt-get install gcc make -y
WORKDIR /opt/
COPY . .
ENTRYPOINT ["make"]
