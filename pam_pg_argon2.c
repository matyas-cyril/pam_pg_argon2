#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <ctype.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

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

    char *start = str;
    while (isspace((unsigned char)*start)) {
        start++;
    }

    // Chaine vide ou avec des espaces
    if (*start == '\0') {
        *str = '\0';
        return str;
    }

    // Trouver la fin et couper les espaces de droite
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';

    // Décaler la chaîne vers le début, au besoin.
    if (start != str) {
        memmove(str, start, (end - start) + 2); // +2 pour inclure le '\0'
    }

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
static Config* load_config(pam_handle_t *pamh, const char *fileName) {

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
    config->timeout = 3;

    char line[MAX_LINE_LEN];
    char *line_trimmed;

    while (fgets(line, sizeof(line), file)) {

        line_trimmed = trim_space(line);
        
        if (line_trimmed[0] == '\n' || line_trimmed[0] == '\r' || line_trimmed[0] == '#') {
            continue;
        }

        char *key = strtok(line_trimmed, "=");
        char *value = strtok(NULL, "\n\r");

        if (key && value) {
            char clean_key[256];
            char clean_value[MAX_LINE_LEN];

            clean_string(clean_key, key);
            clean_string(clean_value, value);

            if (strcmp(clean_key, "host") == 0) {
                strncpy(config->host, clean_value, sizeof(config->host) - 1);
            } 
            else if (strcmp(clean_key, "port") == 0) {

                // Vérifie la validité du port
                int p = atoi(clean_value);
                if (p >= 1 && p <= 65535) {
                    config->port = (unsigned int)p;
                } else {
                    pam_syslog(pamh, LOG_ERR, "Invalid port value '%s' in '%s' config file", clean_value, fileName);
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
            else if (strcmp(clean_key, "timeout") == 0) {

                // Vérifie la validité du timeout
                int t = atoi(clean_value);
                if (t >= 0 && t <= 3600) {
                    config->timeout = (unsigned int)t;
                } else {
                    pam_syslog(pamh, LOG_ERR, "Invalid timeout value '%s' in '%s' config file", clean_value, fileName);
                    fclose(file);
                    return NULL;
                }

            }
            else {
                pam_syslog(pamh, LOG_ERR, "Invalid option name '%s' in '%s' config file", clean_key, fileName);
                fclose(file);
                return NULL;
            }
        }
    }

    fclose(file);
    pam_syslog(pamh, LOG_INFO, "Succes load '%s' config file", fileName);
    return config;
}

static void secure_clear(void *ptr, size_t len) {

    if (ptr == NULL) return;
    volatile unsigned char *p = ptr;
    while (len > 0) {
        *p++ = 0;
        len--;
    }

}

static const char *get_option(int argc, const char **argv, const char *name) {
    if (name == NULL || argv == NULL) return NULL;
    size_t name_len = strlen(name);

    for (int i = 0; i < argc; i++) {
        if (argv[i] != NULL && strncmp(argv[i], name, name_len) == 0 && argv[i][name_len] == '=') {
            return argv[i] + name_len + 1;
        }
    }
    return NULL;
}

static int check_auth(pam_handle_t *pamh, const char *login, const char *password, int argc, const char **argv) {
 
    int status = PAM_AUTH_ERR; // Par défaut on dit que c'est un échec
    const char *conf_file;

    // Récupérer le path du fichier de configuration fourni dans PAM
    conf_file = get_option(argc, argv, "conf");
    if (conf_file == NULL || conf_file[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: option conf= must be defined in conf PAM");
        return PAM_SERVICE_ERR;
    }

    const Config *config;
    // Traitement du fichier de configuration
    config = load_config(pamh, conf_file);
    if (config == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to init configuration");
        return PAM_SERVICE_ERR;
    }

    return status;
}

/*
    APPELS EXT DES FONCTIONS POUR PAM
*/

// 
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void) pamh; (void) flags; (void) argc; (void) argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void) pamh; (void) flags; (void) argc; (void) argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    
    const char *login = NULL;
    const char *password = NULL;
    int status;
    (void) flags;

    status = pam_get_user(pamh, &login, NULL);
    if (status != PAM_SUCCESS || login == NULL || login[0] == '\0') {
        pam_syslog(pamh, LOG_NOTICE, "pam_pg_argon2: failed to get login");
        return PAM_AUTH_ERR;
    }

    status = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (status != PAM_SUCCESS || password == NULL) {
        pam_syslog(pamh, LOG_NOTICE, "pam_pg_argon2: failed to get password");
        return PAM_AUTH_ERR;
    }

    int auth_result = check_auth(pamh, login, password, argc, argv);

    if (password != NULL) {
        secure_clear((void *)password, strlen(password));
    }

    return auth_result;
}
