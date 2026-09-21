
# Config du compilateur
CC=gcc

# Def des drapeaux pour la compilation
CFLAGS=-fPIC -shared -Wall -Wextra -O2 -fstack-protector-strong -D_GNU_SOURCE -Wl,-z,defs

# -lpq -largon2 DOIVENT être placées dans LDFLAGS !!!
LDFLAGS=-lpq -largon2 -lpam -linih

SRC=pam_pg_argon2.c
TARGET = pam_pg_argon2.so

PAM_DIR := $(shell if [ -d /lib/x86_64-linux-gnu/security ]; then echo /lib/x86_64-linux-gnu/security; \
             elif [ -d /usr/lib64/security ]; then echo /usr/lib64/security; \
             else echo /lib/security; fi)

.PHONY: build clean install uninstall

.$(TARGET): 
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $< $(LDFLAGS)

build: .$(TARGET)

clean:
	rm -f $(TARGET)

install: .$(TARGET)
	@echo "\033[32mInstall PAM module in $(PAM_DIR)\033[0m"
	install -m 755 -d $(PAM_DIR)
	install -m 644 $(TARGET) $(PAM_DIR)/$(TARGET)
	@echo "\033[32mCreate the compatibility symlink for Saslauthd\033[0m"
	mkdir -p /usr/lib/security
	ln -sf $(PAM_DIR)/$(TARGET) /usr/lib/security/$(TARGET)
	@echo "\033[32mPAM module installed successfully\033[0m"

uninstall:
	@echo "\033[32mUninstall PAM module $(PAM_DIR)/$(TARGET)\033[0m"
	rm -f $(PAM_DIR)/$(TARGET)
	rm -f /usr/lib/security/$(TARGET)

