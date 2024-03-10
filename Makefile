CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lm -L./ -lgmp
INCLUDES = -I./
SRCS = ./*.c
MAIN = cryptography.exe


all: $(MAIN)
	
$(MAIN): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS)


clean:
	rm ./cryptography.exe
