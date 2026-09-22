
# Config du compilateur
CC=gcc

# Def des drapeaux pour la compilation
CFLAGS=-fPIC -shared -Wall -Wextra -O2 -fstack-protector-strong -D_GNU_SOURCE -Wl,-z,defs

# -lpq -largon2 DOIVENT être placées dans LDFLAGS !!!
LDFLAGS=-lpq -largon2 -lpam -linih

# Var pour la compilation via Docker
DOCKER_IMG=debian
DOCKER_IMG_TAGS=13-slim

# Def du fichier et de la librairie (.so) après compilation
SRC=pam_pg_argon2.c
TARGET=pam_pg_argon2.so

# Détermination du dossier PAM
PAM_DIR := $(shell if [ -d /lib/x86_64-linux-gnu/security ]; then echo /lib/x86_64-linux-gnu/security; \
             elif [ -d /usr/lib64/security ]; then echo /usr/lib64/security; \
             else echo /lib/security; fi)

.PHONY: all build clean install uninstall docker

.$(TARGET): 
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

.root: 
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "\033[31mInsufficient permissions to execute make command\033[0m"; \
	fi

all: install

build: .$(TARGET)

clean:
	@rm -fv $(TARGET)

install: .$(TARGET) .root
	@echo "\033[32mInstall PAM module in $(PAM_DIR)\033[0m"
	install -m 755 -d $(PAM_DIR)
	install -m 644 $(TARGET) $(PAM_DIR)/$(TARGET)
	@echo "\033[32mCreate the compatibility symlink for Saslauthd\033[0m"
	mkdir -p /usr/lib/security
	ln -sf $(PAM_DIR)/$(TARGET) /usr/lib/security/$(TARGET)
	@echo "\033[32mPAM module installed successfully\033[0m"

uninstall: .root
	@echo "\033[32mUninstall PAM module $(PAM_DIR)/$(TARGET)\033[0m"
	@rm -fv $(PAM_DIR)/$(TARGET)
	@rm -fv /usr/lib/security/$(TARGET)

docker:
	@rm -fv $(TARGET);
	@docker run --rm \
		-e HOST_UID="$$(id -u)" \
		-e HOST_GID="$$(id -g)" \
		-v /etc/localtime:/etc/localtime:ro \
		-v /etc/timezone:/etc/timezone:ro \
		-v "$$(pwd)":/usr/src/pam_pg_argon2 \
		-w /usr/src/pam_pg_argon2 \
		$(DOCKER_IMG):$(DOCKER_IMG_TAGS) \
		sh -c 'apt-get update && \
			apt-get install -y gcc libargon2-1 libargon2-dev libpam-doc libpam0g-dev libpq-dev libpq5 libssl-dev libinih-dev && \
			rm -f $(TARGET) && \
			gcc -fPIC -shared -Wall -Wextra -O2 -fstack-protector-strong -D_GNU_SOURCE -Wl,-z,defs -o $(TARGET) $(SRC) -lpq -largon2 -lpam -linih && \
			chown $$HOST_UID:$$HOST_GID $(TARGET)'

info:
	@if ! command -v readelf >/dev/null 2>&1; then \
		printf "\033[31mERROR : command 'readelf' not available\033[0m\n" >&2; \
		exit 1; \
	fi
	@if [ ! -f "$(TARGET)" ]; then \
		printf "\033[31mERROR : file '"$(TARGET)"' not exist - use command 'make build' or 'make docker'\033[0m\n" >&2; \
		exit 1; \
	fi
	@for section in .author_info .comment; do \
		printf '\n--- Section %s ---\n' "$$section"; \
		readelf -p "$$section" "$(TARGET)" || true; \
	done