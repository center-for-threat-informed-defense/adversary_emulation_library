CC=gcc
FLAGS=-ggdb -Wall

all: compile


bins:
	mkdir -p ./bin/

compile: bins
	$(CC) $(FLAGS) -I ./inc/ ./src/*.c -o ./bin/rota

clean:
	rm -rf ./bin
