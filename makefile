
## Nécessite les paquets :
#gcc libargon2-1  libargon2-dev  libpam-doc  libpam0g-dev  libpq-dev  libpq5  libssl-dev libinih-dev

# Config du compilateur
CC=gcc

# Def des drapeaux pour la compilation
CFLAGS=-fPIC -shared -Wall -Wextra -O2 -fstack-protector-strong -D_GNU_SOURCE -Wl,-z,defs

# -lpq -largon2 DOIVENT être placées dans LDFLAGS !!!
LDFLAGS=-lpq -largon2 -lpam -linih

SRC=pam_pg_argon2.c
TARGET = pam_pg_argon2.so

.PHONY: build clean

build:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $< $(LDFLAGS)

clean:
	@rm -f $(TARGET)

