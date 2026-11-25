CC=gcc
CFLAGS=-Wall -Wextra

password_manager:
	$(CC) $(CFLAGS) \
	src/main.c \
	src/auth.c \
	src/vault.c \
	src/crypto.c \
	src/logging.c \
	src/utils.c \
	-o password_manager