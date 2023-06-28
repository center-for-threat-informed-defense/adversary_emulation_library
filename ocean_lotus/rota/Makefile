CC=gcc
FLAGS=-ggdb -Wall -DDEBUG

all: compile

bins:
	mkdir -p ./bin/

compile: bins
	$(CC) $(FLAGS) -I ./inc/ $(wildcard ./src/*.c) -o ./bin/rota

clean:
	ipcrm -M 0x0064b2e2
	rm -rf ./bin
	rm -rf ~/.config/au-tostart
	rm -rf ~/.gvfsd
#rm -rf ~/.bashrc
	rm -rf ~/.X11
#rm -rf ~/.dbus
