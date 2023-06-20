CC=gcc
FLAGS=-ggdb -Wall -DDEBUG

all: compile

bins:
	mkdir -p ./bin/

compile: bins
	$(CC) $(FLAGS) -I ./inc/ $(wildcard ./src/*.c) -o ./bin/rota

clean:
	rm -rf ./bin
	rm -rf ~/.config/au-tostart
	rm -rf ~/.gvfsd
#rm -rf ~/.bashrc
	rm -rf ~/.X11
