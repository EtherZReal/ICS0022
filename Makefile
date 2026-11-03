CC=gcc
CFLAGS=-Wall -Wextra

password_manager:
	$(CC) $(CFLAGS) src/main.c -o password_manager