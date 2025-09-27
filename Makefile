CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = tftp.out
SOURCE = tftp_server.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
	rm -f test[0-9]*.txt

.PHONY: clean
