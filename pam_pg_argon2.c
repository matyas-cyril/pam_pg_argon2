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

static void clean_string(char *dest, const char *src) {
    while (isspace((unsigned char)*src)) src++;
    size_t len = strlen(src);
    while (len > 0 && isspace((unsigned char)src[len - 1])) len--;
    if (len >= 2 && ((src[0] == '\'' && src[len - 1] == '\'') || (src[0] == '"' && src[len - 1] == '"'))) {
        src++;
        len -= 2;
    }
    strncpy(dest, src, len);
    dest[len] = '\0';
}

/*
    Charger le fichier de configuration
    Retourner une structure en cas de succès, sinon NULL
*/
static Config* load_config(const char *fileName) {

    FILE *file = fopen(fileName, "r");
    if (!file) {
        syslog(LOG_ERR, "Failed to load file '%s' : %m", fileName);
        return NULL;
    }

    Config *config = malloc(sizeof(Config));
    if (!config) {
        syslog(LOG_ERR, "Memory allocation error for configuration : %m");
        fclose(file);
        return NULL;
    }

    // Définir les valeurs par défaut pour la structure
    strcpy(config->host, "127.0.0.1");
    config->port = 5432;
    strcpy(config->db_name, "");
    strcpy(config->user, "");
    strcpy(config->password, "");
    config->sslmode = false;
    strcpy(config->query, "");

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), file)) {

        *line = trim_space(line);
        
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '#') {
            continue;
        }

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n\r");

        if (key && value) {
            char clean_key[256];
            char clean_value[MAX_LINE_LEN];

            trim_and_clean(clean_key, key);
            trim_and_clean(clean_value, value);

            if (strcmp(clean_key, "host") == 0) {
                strncpy(config->host, clean_value, sizeof(config->host) - 1);
            } 
            else if (strcmp(clean_key, "port") == 0) {

                // Vérifie la validité du port
                int p = atoi(clean_value);
                if (p >= 1 && p <= 65535) {
                    config->port = (unsigned int)p;
                } else {
                    syslog(LOG_ERR, "Invalid port value '%s' in '%s' config file", clean_value, fileName);
                    fclose(file);
                    return NULL;
                }
            } 
            else if (strcmp(clean_key, "db_name") == 0) {
                strncpy(config->db_name, clean_value, sizeof(config->db_name) - 1);
            } 
            else if (strcmp(clean_key, "user") == 0) {
                strncpy(config->user, clean_value, sizeof(config->user) - 1);
            } 
            else if (strcmp(clean_key, "password") == 0) {
                strncpy(config->password, clean_value, sizeof(config->password) - 1);
            } 
            else if (strcmp(clean_key, "sslmode") == 0) {
                if (strcmp(clean_value, "true") == 0 || strcmp(clean_value, "1") == 0) {
                    config->sslmode = true;
                } else {
                    config->sslmode = false;
                }
            } 
            else if (strcmp(clean_key, "query") == 0) {
                strncpy(config->query, clean_value, sizeof(config->query) - 1);
            }
        }
    }

    fclose(file);
    syslog(LOG_INFO, "Succes load '%s' config file", fileName);
    return config;
}


