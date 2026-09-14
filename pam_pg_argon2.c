#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_LINE_LEN 2048
#define MAX_OPT_LEN 256
#define MAX_QUERY_LEN 2048

/*
Structure du fichier ini par défaut :
host = '127.0.0.1'
port = 5432
db_name = ''
user = ''
password = ''
sslmode = false
query = ''
timeout = 3
 */
typedef struct {
    char host[MAX_OPT_LEN];
    unsigned int port;
    char db_name[MAX_OPT_LEN];
    char user[MAX_OPT_LEN];
    char password[MAX_OPT_LEN];
    bool sslmode;
    char query[MAX_QUERY_LEN];
    unsigned int timeout;
} Config;

// Supprimer les espaces de gauche et de droite d'une chaine de carac
static char* trim_space(char *str) {
    if (str == NULL) return NULL;

    // 1. Déplacement du pointeur pour sauter les espaces du début (Left Trim)
    // (unsigned char) est requis par ctype.h pour éviter des comportements indéfinis
    while (isspace((unsigned char)*str)) {
        str++;
    }

    // Si la chaîne était vide ou ne contenait que des espaces
    if (*str == '\0') {
        return str;
    }

    // 2. Nettoyage des espaces de la fin (Right Trim)
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }

    // Écriture du nouveau caractère de fin de chaîne
    *(end + 1) = '\0';

    return str;
}
