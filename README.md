# pam_pg_argon2

# 1. Présentation

Module PAM permettant d'authentifier des utilisateurs à partir d'informations stockées dans une BDD PostgreSQL.  
Le hash des mots de passe est l'argon2id.  

# 2. Compilation

## 2.1 Prérequis

Pour la comilation (hors méthode 2.2.3 Docker), Vérifier la présence des dépendances de developpement.  
Exemple sur Debian :
```bash
sudo apt update
sudo apt install build-essential gcc libargon2-1 libargon2-dev libpam-doc libpam0g-dev libpq-dev libpq5 libssl-dev libinih-dev
```

## 2.2 Compilation 

Cloner le dépot.

### 2.2.1 makefile

``` bash
make build
```

### 2.2.2 gcc

``` bash
gcc -fPIC -shared -Wall -Wextra -O2 -fstack-protector-strong -D_GNU_SOURCE -Wl,-z,defs -o pam_pg_argon2.so pam_pg_argon2.c -lpq -largon2 -lpam -linih
```

### 2.2.3 Docker

Compilation en utilisant la création d'un container temporaire.  
Nécessite la présente de Docker sur l'hôte.  

Dans l'exemple ci-dessous la compilation est effectuée en utilisant une image Debian Trixie (13)

``` bash
docker run --rm \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -v "$(pwd)":/usr/src/myapp \
    -w /usr/src/myapp \
    debian:13-slim \
    sh -c 'apt-get update &&
           apt-get install -y gcc libargon2-1 libargon2-dev libpam-doc libpam0g-dev libpq-dev libpq5 libssl-dev libinih-dev && \
           rm -f pam_pg_argon2.so && \
           gcc -fPIC -shared -Wall -Wextra -O2 -fstack-protector-strong -D_GNU_SOURCE -Wl,-z,defs -o pam_pg_argon2.so pam_pg_argon2.c -lpq -largon2 -lpam -linih && \
           chown "$HOST_UID:$HOST_GID" pam_pg_argon2.so'
```
# 3. Installation

# 3.1 manuelle

# 3.2 makefile

``` bash
make install
```

# 4. Utilisation

## 4.1 Exemple de schéma de BDD

``` sql
--- Table Users
CREATE TABLE IF NOT EXISTS Users (
	id_user UUID PRIMARY KEY DEFAULT uuidv7(),
	username VARCHAR(64) NOT NULL,
	password VARCHAR(256) NOT NULL CHECK (password ~ '^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'),
	not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
	expiration TIMESTAMPTZ,
	disabled BOOLEAN NOT NULL DEFAULT false,
	description TEXT,
	
	--On ne peut pas avoir la date d'expiration <= à la date d'utilisation
	CONSTRAINT issued_after_not_before CHECK (expiration IS NULL OR expiration > not_before)
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_idx ON Users(username);

--- View des logins actifs
CREATE OR REPLACE VIEW V_Logins AS
    SELECT id_user, username, password AS password_hash
    FROM users
    WHERE disabled = false
        AND not_before < now()
        AND (expiration IS NULL OR expiration > now());
```