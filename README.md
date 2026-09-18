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

# 4. Configuration

La librairie pam_pg_argon2.so a besoin d'un fichier configuration et d'un fichier de configuration PAM pour être utilisable.

## 4.1 Fichier ini

La configuration de la librairie PAM est possible uniquement par un fichier de type **ini**.  
Ce fichier est composé de 2 sections : 
- POSTGRES
- APP

### 4.1.1 Sections

#### 4.1.1.1 [POSTGRES]

| CLEF | TYPE | DEFAUT | DÉSIGNATION |
|------|------|--------|-------------|
| **host** | string | 127.0.0.1 | Adresse de connexion à la BDD |
| **port** | int | 5432 | Port de connexion à la BDD |
| **db_name** | string | | Nom de la BDD |
| **user** | string | | Login à la BDD |
| **password** | string | | Mot de passe du Login |
| **sslmode** | bool | false | Activer la connexion SSL à la BDD |
| **timeout** | int | 3 | Définir en seconde la durée max de la requête à la BDD |

#### 4.1.1.2 [APP]

| CLEF | TYPE | DEFAUT | DÉSIGNATION |
|------|------|--------|-------------| 
| **query** | string | | Requête SQL permettant d'obtenir le hash en fonction du login.<BR>Le passage du login se fait par le champ **$1**.<BR>**$1** est obligatoire dans la déclaration. |
| **debug** | bool | false | Activer le mode debug |

### 4.1.2 Structure complète du fichier ini

```ini
[POSTGRES]
host = 127.0.0.1
port = 5432
db_name = 
user = 
password = 
sslmode = false
timeout = 3

[APP]
query = 
debug = false
```

### 4.1.3 Exemple de fichier ini

Ci-dessous un fichier ini, correspondant à une BDD (TestBDD) dont l'IP de connexion est 192.168.16.64, l'utilisateur user_login et le mot de passe _VERY_STRONG_.  

La requête SQL correspond au schéma de l'exemple (4.2).  

``` ini 
[POSTGRES]
host = 192.168.16.64
db_name = TestBDD
user = user_login
password = _VERY_STRONG_

[APP]
query = SELECT password_hash FROM V_Logins WHERE username = $1 LIMIT 1
```

## 4.2 Exemple de schéma de BDD

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
## 4.3 PAM Configuration

Elle définit les règles d'authentification et de contrôle d'accès pour un service Linux.

### 4.3.1 Syntaxe

La session tente d'authentifier l'utilisateur via une base PostgreSQL avec un chiffrement Argon2.  
Si le mot de passe est valide, la gestion du compte autorise immédiatement l'accès sans restriction supplémentaire.  

Ce fichier doit être présent dans **/etc/pam.d/**

Le fichier doit contenir les informations suivantes :

``` bash
auth    required    pam_pg_argon2.so onf_file=_PATH_COMPLET_DU_FICHIER_INIT_
account required    pam_permit.so
```

### 4.3.2 Exemple

``` bash
auth    required    pam_pg_argon2.so conf_file=/etc/security/pam_pg_argon2.ini
account required    pam_permit.so
```

# 5. Installation de la librairie

## 5.1 Manuelle

L'installation manuelle correspond à un système Debian 13.

Le fichier PAM comportant les règles d'authentification (4.3) est présent dans /etc/pam.d/ avec le nom de votre choix.

``` bash
# Copier la librairie compilée
$ sudo cp pam_pg_argon2.so /usr/lib/x86_64-linux-gnu/security/pam_pg_argon2.so

# Changer le propriètaire et le droits
$ sudo chown root:root /usr/lib/x86_64-linux-gnu/security/pam_pg_argon2.so && \
  sudo chmod 644 /usr/lib/x86_64-linux-gnu/security/pam_pg_argon2.so

# Création du répertoire /usr/lib/security
$ sudo mkdir -p /usr/lib/security && \
  sudo chown root:root /usr/lib/security && \
  sudo chmod 755 /usr/lib/security

# Création du lien symbolique
$ sudo ln -sf /lib/x86_64-linux-gnu/security/pam_pg_argon2.so /usr/lib/security/pam_pg_argon2.so
```

## 5.2 Makefile

``` bash
make install
```
