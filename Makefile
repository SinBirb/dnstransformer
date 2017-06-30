CC=gcc
CFLAGS=-Wall -g -Og

all:
	$(CC) -o dnstransformer $(CFLAGS) src/dnstransformer.c src/smlog.c

clean:
	rm dnstransformer
