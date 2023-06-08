CC=gcc
FLAGS=-Wall

all: compile


bins:
	mkdir -p ./bin/

compile: bins
	$(CC) -I ./inc/ ./src/*.c -o ./bin/rota

clean:
	rm -rf ./bin
