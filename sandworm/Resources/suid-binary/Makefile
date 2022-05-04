default: suid-binary

suid-binary.o: suid-binary.c
	gcc -c suid-binary.c -o suid-binary.o

suid-binary: suid-binary.o
	gcc suid-binary.o -o suid-binary
	strip suid-binary

clean:
	-rm -f suid-binary.o
	-rm -f suid-binary