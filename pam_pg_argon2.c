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

#include <argon2.h>
#include <postgresql/libpq-fe.h>

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
debug = false
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
    bool debug;
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

static void clean_string(char *dest, size_t dest_size, const char *src) {
    if (dest_size == 0) return;
    while (isspace((unsigned char)*src)) src++;
    size_t len = strlen(src);
    while (len > 0 && isspace((unsigned char)src[len - 1])) len--;
    if (len >= 2 && ((src[0] == '\'' && src[len - 1] == '\'') || (src[0] == '"' && src[len - 1] == '"'))) {
        src++;
        len -= 2;
    }
    if (len >= dest_size) len = dest_size - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

/*
    Charger le fichier de configuration
    Retourner une structure en cas de succès, sinon NULL
*/
static Config* load_config(pam_handle_t *pamh, const char *fileName) {

    FILE *file = fopen(fileName, "r");
    if (!file) {
        pam_syslog(pamh, LOG_ERR, "Failed to load file '%s' : %m", fileName);
        return NULL;
    }

    Config *config = malloc(sizeof(Config));
    if (!config) {
        pam_syslog(pamh, LOG_ERR, "Memory allocation error for configuration : %m");
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
    config->debug = false;
    strcpy(config->query, "");
    config->timeout = 3;

    char line[MAX_LINE_LEN];
    char *line_trimmed;

    while (fgets(line, sizeof(line), file)) {

        line_trimmed = trim_space(line);
        
        if (line_trimmed[0] == '\n' || line_trimmed[0] == '\r' || line_trimmed[0] == '#') {
            continue;
        }

        char *key = strchr(line_trimmed, '=');
        char *value = strtok(NULL, "\n\r");

        if (key && value) {
            char clean_key[256];
            clean_string(clean_key, sizeof(clean_key), key);

            if (strcmp(clean_key, "host") == 0) {
                clean_string(config->host, sizeof(config->host), value);
            } 
            else if (strcmp(clean_key, "port") == 0) {
                char clean_val[64];
                clean_string(clean_val, sizeof(clean_val), value);
                int p = atoi(clean_val);
                if (p >= 1 && p <= 65535) {
                    config->port = (unsigned int)p;
                } else {
                    pam_syslog(pamh, LOG_ERR, "Invalid port value '%s' in '%s' config file", clean_val, fileName);
                    fclose(file);
                    free(config);
                    return NULL;
                }
            }
            else if (strcmp(clean_key, "db_name") == 0) {
                clean_string(config->db_name, sizeof(config->db_name), value);
            }
            else if (strcmp(clean_key, "user") == 0) {
                clean_string(config->user, sizeof(config->user), value);
            }
            else if (strcmp(clean_key, "password") == 0) {
                clean_string(config->password, sizeof(config->password), value);
            }
            else if (strcmp(clean_key, "sslmode") == 0) {
                char clean_val[64];
                clean_string(clean_val, sizeof(clean_val), value);
                config->sslmode = (strcmp(clean_val, "true") == 0 || strcmp(clean_val, "1") == 0);
            }
            else if (strcmp(clean_key, "debug") == 0) {
                char clean_val[64];
                clean_string(clean_val, sizeof(clean_val), value);
                config->debug = (strcmp(clean_val, "true") == 0 || strcmp(clean_val, "1") == 0);
            }
            else if (strcmp(clean_key, "query") == 0) {
                clean_string(config->query, sizeof(config->query), value);
            }
            else if (strcmp(clean_key, "timeout") == 0) {
                char clean_val[64];
                clean_string(clean_val, sizeof(clean_val), value);
                int t = atoi(clean_val);
                if (t >= 0 && t <= 3600) {
                    config->timeout = (unsigned int)t;
                } else {
                    pam_syslog(pamh, LOG_ERR, "Invalid timeout value '%s' in '%s' config file", clean_val, fileName);
                    fclose(file);
                    free(config);
                    return NULL;
                }
            }
            else {
                pam_syslog(pamh, LOG_ERR, "Invalid option name '%s' in '%s' config file", clean_key, fileName);
                fclose(file);
                free(config);
                return NULL;
            }
        }

    }

    fclose(file);
    pam_syslog(pamh, LOG_INFO, "Succes load '%s' config file", fileName);
    return config;
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

    // Déclaration pour utilisation de goto
    Config *config = NULL;
    PGconn *cnx = NULL;
    PGresult *rslt = NULL;

    // Récupérer le path du fichier de configuration fourni dans PAM
    const char *conf_file = get_option(argc, argv, "conf");
    if (conf_file == NULL || conf_file[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: option conf= must be defined in conf PAM");
        return PAM_SERVICE_ERR;
    }

    // Traitement du fichier de configuration
    config = load_config(pamh, conf_file);
    if (config == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to init configuration");
        return PAM_SERVICE_ERR;
    }

    // Définition de la connexion
    const char *keywords[] = {
        "host",
        "port",
        "dbname",
        "user",
        "password",
        "sslmode",
        "connect_timeout",
         NULL
    };

    char port_str[12], timeout_str[12];
    snprintf(port_str, sizeof(port_str), "%u", config->port);
    snprintf(timeout_str, sizeof(timeout_str), "%u", config->timeout);
    
    const char *values[] = {
        config->host,
        port_str,
        config->db_name,
        config->user,
        config->password,
        config->sslmode ? "require" : "disable",
        timeout_str,
        NULL
    };

    // Essai de connexion
    cnx = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(cnx) != CONNECTION_OK) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed bdd connection - %s",PQerrorMessage(cnx));
        goto defer;
    }

    const char *params[1];
    params[0] = login;

    // Traitement de la requête
    rslt = PQexecParams(cnx, config->query, 1, NULL, params, NULL, NULL, 0);

    if (rslt == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: query failed - %s", PQerrorMessage(cnx));
        goto defer;
    }

    if (PQresultStatus(rslt) != PGRES_TUPLES_OK) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: query respond not valid - %s", PQresultErrorMessage(rslt));
        goto defer;
    }

    // Protection stricte contre les attaques temporelles
    char dummy_hash[] = "$argon2id$v=19$m=65536,t=3,p=4$bXlzYWx0bXlzYWx0$vVpBdm1mZXFlR3NuR2Z2dW1GQ0F3QT09"; 
    const char *hash_to_verify = dummy_hash;
    int user_found = 0;

    const char *stored_hash = NULL;
    if (PQntuples(rslt) == 1 && !PQgetisnull(rslt, 0, 0)) {
        stored_hash = PQgetvalue(rslt, 0, 0);
        if (stored_hash != NULL && stored_hash[0] != '\0') {
            hash_to_verify = stored_hash;
            user_found = 1;
        }
    }

    int argon_status = argon2id_verify(hash_to_verify, password, strlen(password));
    if(user_found && argon_status == ARGON2_OK) {
        status = PAM_SUCCESS;
    } else {
        if (argon_status != ARGON2_OK && argon_status != ARGON2_VERIFY_MISMATCH) {
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: argon2 error - %s", argon2_error_message(argon_status));
        }
    }

    defer:
        if (rslt != NULL) {
            PQclear(rslt);
        }

        if (cnx != NULL) {
            PQfinish(cnx);
        }

        if (config != NULL) {
            free(config);
        }

    return status;
}

/*
    APPELS EXT DES FONCTIONS POUR PAM
*/
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
    char *local_password = NULL;
    (void) flags;

    int status = pam_get_user(pamh, &login, NULL);
    if (status != PAM_SUCCESS || login == NULL || login[0] == '\0') {
        pam_syslog(pamh, LOG_NOTICE, "pam_pg_argon2: failed to get login");
        return PAM_AUTH_ERR;
    }

    status = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (status != PAM_SUCCESS || password == NULL) {
        pam_syslog(pamh, LOG_NOTICE, "pam_pg_argon2: failed to get password");
        return PAM_AUTH_ERR;
    }

    local_password = strdup(password);
    if (local_password == NULL) {
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: memory allocation failure");
            return PAM_BUF_ERR;
    }
    
    int auth_result = check_auth(pamh, login, password, argc, argv);

    // Clean du buffer du mot de passe
    if (local_password != NULL) {
        size_t len = strlen(local_password);
        if (len > 0) {
            explicit_bzero(local_password,len);
            free(local_password);
            local_password = NULL;
        }

    }
    
    return auth_result;
}
