#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ini.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <argon2.h>
#include <postgresql/libpq-fe.h>

#define MAX_HOST_LEN  256
#define MAX_USER_LEN  64
#define MAX_PASS_LEN  512
#define MAX_DB_LEN    64
#define MAX_QUERY_LEN 4096
#define MAX_ERROR_LEN 256

#define FILENAME_ARG   "conf_file"
#define FULL_PATH_SIZE 4096

/*
Structure du fichier ini par défaut :
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
 */
typedef struct {
    char host[MAX_HOST_LEN];
    unsigned int port;
    char db_name[MAX_DB_LEN];
    char user[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
    bool sslmode;
    bool debug;
    char query[MAX_QUERY_LEN];
    unsigned int timeout;
} Config;

typedef struct {
    Config *cfg;
    bool has_error;
    int error_line;
    char error_msg[MAX_ERROR_LEN];
} ParseConfig;

static bool parse_bool(const char *val) {
    return (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0);
}

// Supprime les espaces en debut et fin de chaine
static bool trim(const char *src, char *dest, size_t dest_size) {

    if (!dest || dest_size == 0) return false;

    if (!src) { *dest = '\0'; return false; }

    // Supprimer les espaces au début
    while (isspace((unsigned char)*src)) src++;
    
    // Calculer la longueur sans les espaces de fin
    size_t src_len = strlen(src);
    while (src_len > 0 && isspace((unsigned char)src[src_len - 1])) src_len--;

    if (src_len >= dest_size) { dest[0] = '\0'; return false; }

    memcpy(dest, src, src_len);
    dest[src_len] = '\0';

    return true;
}

// Traitement de la configuration
static int handler_config(void* config, const char* section, const char* name, const char* value) {

    ParseConfig* ctx = (ParseConfig*)config;
    Config* cfg = ctx->cfg;

    #define MATCH_SECTION(s) (strcasecmp(section, s) == 0)
    #define MATCH_KEY(n) (strcasecmp(name, n) == 0)

    //
    int ret = 1; // 1 = succès par défaut

    // Section [POSTGRES]
    if (MATCH_SECTION("POSTGRES")) {    

        if (MATCH_KEY("host")) {

            if (!trim(value, cfg->host, sizeof(cfg->host))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            }

        } else if (MATCH_KEY("port")) {

            char clean_port[12];
            if (!trim(value, clean_port, sizeof(clean_port))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            } else {
                char *end;
                int port = (int)strtol(clean_port, &end, 10);

                if (*end != '\0') {
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value not an integer for '%s.%s' key", section, name);
                    ret = 0;
                } else if (port >= 1 && port <= 65535) {
                    cfg->port = (unsigned int)port;
                } else {
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be [1-65535] for '%s.%s' key", section, name);
                    ret = 0;
                }
            }

        } else if (MATCH_KEY("db_name")) {

            if (!trim(value, cfg->db_name, sizeof(cfg->db_name))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            }

        } else if (MATCH_KEY("user")) {

            if (!trim(value, cfg->user, sizeof(cfg->user))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            }

        } else if (MATCH_KEY("password")) {

            if (!trim(value, cfg->password, sizeof(cfg->password))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            }

        } else if (MATCH_KEY("sslmode")) {

            char clean_ssl[16];
            if (!trim(value, clean_ssl, sizeof(clean_ssl))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            } else if (strncmp(clean_ssl, "true", 4) == 0 || strncmp(clean_ssl, "false", 5) == 0) {
                cfg->sslmode = parse_bool(clean_ssl);
            } else {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be 'true' or 'false' for '%s.%s' key", section, name);
                ret = 0;
            }

        } else if (MATCH_KEY("timeout")) {  

            char clean_timeout[12];
            if (!trim(value, clean_timeout, sizeof(clean_timeout))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            } else {
                char *end;
                int timeout = (int)strtol(clean_timeout, &end, 10);

                if (*end != '\0') {
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value not an integer for '%s.%s' key", section, name);
                    ret = 0;
                } else if (timeout >= 0 && timeout <= 3600) {
                    cfg->timeout = (unsigned int)timeout;
                } else {
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be [0-3600] for '%s.%s' key", section, name);
                    ret = 0;
                }
            }

        } else {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Key '%s.%s' does not exist", section, name);
            ret = 0;
        }
    }

    // Section [APP]
    else if (MATCH_SECTION("APP")) {

        if (MATCH_KEY("query")) {

            if (!trim(value, cfg->query, sizeof(cfg->query))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            }

            // On vérifie que la requête contient $1. Attention ce n'est pas un contrôle SQL.
            char *p = cfg->query;
            bool flag = false;
            while ((p = strstr(p, "$1")) != NULL) {
                // On vérifie que le caractère juste après n'est pas un chiffre
                if (!isdigit((unsigned char)p[2])) {
                    flag = true;
                    break;
                }
                p += 2; // Avance pour continuer la recherche si c'était par ex on a $10
            }

            if (!flag) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Query in '%s.%s' must contain placeholder '$1'", section, name);
                ret = 0;
            }


        } else if (MATCH_KEY("debug")) {

            char clean_debug[16];
            if (!trim(value, clean_debug, sizeof(clean_debug))) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid value for '%s.%s'", section, name);
                ret = 0;
            } else if (strncmp(clean_debug, "true", 4) == 0 || strncmp(clean_debug, "false", 5) == 0) {
                cfg->debug = parse_bool(clean_debug);
            } else {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be 'true' or 'false' for '%s.%s' key", section, name);
                ret = 0;
            }

        } else {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Key '%s.%s' does not exist", section, name);
            ret = 0;
        }

    } else {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Section '%s' does not exist", section);
        ret = 0;
    }
    
    // Fermeture des macros
    #undef MATCH_SECTION
    #undef MATCH_KEY

    // unique return à cause des macros
    return ret; // Succes: 1
}

/*
    Charger le fichier de configuration
    Retourner une structure en cas de succès, sinon NULL
*/
static Config* load_config(pam_handle_t *pamh, const char *fileName) {

    Config *config = malloc(sizeof(Config));
    if (config == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: memory allocation error to init configuration file '%s': %m", fileName);
        return NULL;
    }

    // Déclaration de config avec les valeurs par défaut.
    *config = (Config){
        .host = "127.0.0.1",
        .port = 5432,
        .db_name = "",
        .user = "",
        .password = "",
        .sslmode = false,
        .debug = false,
        .query = "",
        .timeout = 3
    };

    ParseConfig ctx = {
        .cfg = config,
        .has_error = false,
        .error_msg = ""
    };

    // Succès si status = 0
    int status = ini_parse(fileName, handler_config, &ctx);
    if (status != 0) {
        if (status > 0) {
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to load configuration file '%s': %s", fileName, ctx.error_msg[0] != '\0' ? ctx.error_msg : "syntax error INI");
        } else if (status == -1) {
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to load configuration file '%s'", fileName);
        } else {
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to load configuration file '%s': memory allocation error", fileName);
        }
        
        explicit_bzero(config, sizeof(Config));
        free(config);
        return NULL;
    }

    if (ctx.cfg->debug) {

        // Masquer le mot de passe pour le mode debug
        char masked_passwd[MAX_PASS_LEN];
        size_t len_passwd = strlen(ctx.cfg->password);
        for (size_t i = 0; i < len_passwd; i++) masked_passwd[i] = '*';
        masked_passwd[len_passwd] = '\0';

        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] configuration file '%s' loaded successfully", fileName);

        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] host    : %s", ctx.cfg->host);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] port    : %u", ctx.cfg->port);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] db_name : %s", ctx.cfg->db_name);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] user    : %s", ctx.cfg->user);
        
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] password: %s", masked_passwd);
        explicit_bzero(masked_passwd, sizeof(masked_passwd));
        
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] timeout : %u", ctx.cfg->timeout);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] sslmode : %s", ctx.cfg->sslmode?"true":"false");
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] debug   : %s", ctx.cfg->debug?"true":"false");
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] query   : %s", ctx.cfg->query);

    } else {
        pam_syslog(pamh, LOG_INFO, "pam_pg_argon2: configuration file '%s' loaded successfully", fileName);
    }

    return ctx.cfg;
}

/*
    Permet d'obtenir le full path d'un fichier.
    En cas de succès la fonction retourne true, sinon false
    src_path contient le fichier
    full_path contient le fichier avec le path complet
    ex: 
        src_path = "~/.bashrc"
        full_path = "/home/rene.lataupe/.bashrc"
*/
static bool get_full_path(const char *src_path, char **full_path) {

if (src_path == NULL || full_path == NULL) return false;

    // Refuser explicitement les chemins relatifs au home utilisateur
    if (src_path[0] == '~') return false;

    char *local_full_path = realpath(src_path, NULL);
    if (local_full_path == NULL) return false;

    // Vérification des droits et du type de fichier
    struct stat buffer;

    if (stat(local_full_path, &buffer) == 0 && S_ISREG(buffer.st_mode) && access(local_full_path, R_OK) == 0) {
        *full_path = local_full_path;
        return true;
    }   

    free(local_full_path);
    return false;
}

// Extraire le nom du fichier de conf à partir d'une forme d'argument 
// Si erreur retourne false, sinon charge dest et retourne true
static bool get_option(int argc, const char **argv, const char *name_key, char **file) {

    if (name_key == NULL || argv == NULL || file == NULL) return false;

    size_t name_key_len = strlen(name_key);

    for (int i = 0; i < argc; i++) {
        if (argv[i] == NULL) continue;

        if (strncmp(argv[i], name_key, name_key_len) == 0 && argv[i][name_key_len] == '=') {

            const char *value = argv[i] + name_key_len + 1;
            char dest[FULL_PATH_SIZE];

            if (!trim(value, dest, sizeof(dest))) return false;

            return get_full_path(dest, file);
        }
    }

    return false;
}

static int check_auth(pam_handle_t *pamh, const char *login, const char *password, int argc, const char **argv) {
 
    int status = PAM_AUTH_ERR; // Par défaut on dit que c'est un échec

    Config *config = NULL;
    PGconn *cnx = NULL;
    PGresult *rslt = NULL;

    // Récupérer le path du fichier de configuration fourni dans PAM
    char *conf_file = NULL;

    if (!get_option(argc, argv, FILENAME_ARG, &conf_file)) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: option '%s=' must be defined in conf PAM", FILENAME_ARG);
        return PAM_SERVICE_ERR;
    }

    // Traitement du fichier de configuration
    config = load_config(pamh, conf_file);
    if (config == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to init configuration");
        if (conf_file != NULL) free(conf_file);
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
        config->sslmode?"require":"disable",
        timeout_str,
        NULL
    };

    // Essai de connexion
    cnx = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(cnx) != CONNECTION_OK) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed bdd connection - %s", PQerrorMessage(cnx));
        goto defer;
    }

    if (config->debug)
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] success bdd connection - '%s:%d' for user '%s'", config->host, config->port, config->user);

    const char *params[1];
    params[0] = login;

    // Traitement de la requête
    rslt = PQexecParams(cnx, config->query, 1, NULL, params, NULL, NULL, 0);

    if (rslt == NULL) {
        if (config->debug)
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: query failed - %s", PQerrorMessage(cnx));
        goto defer;
    }

    if (PQresultStatus(rslt) != PGRES_TUPLES_OK) {
        if (config->debug)
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: query respond not valid - %s", PQresultErrorMessage(rslt));
        goto defer;
    }

    if (config->debug) 
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] success query for login '%s'", login);
    

    // Protection stricte contre les attaques temporelles
    static const char * const DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$bXlzYWx0bXlzYWx0$vVpBdm1mZXFlR3NuR2Z2dW1GQ0F3QT09";

    const char *hash_to_verify = DUMMY_HASH;
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
    if (user_found && argon_status == ARGON2_OK) {
        status = PAM_SUCCESS;
    } else {
        if (argon_status != ARGON2_OK && argon_status != ARGON2_VERIFY_MISMATCH) {
            pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: argon2 error - %s", argon2_error_message(argon_status));
        }
    }

defer:

    if (config->debug)
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] check auth return value '%d'", status);

    if (conf_file != NULL) {
        free(conf_file);
        if (config->debug)
            pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] free configuration file");
    }
    
    if (rslt != NULL) {
        PQclear(rslt);
        if (config->debug)
            pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] clear BDD request for login '%s'", login);
    }
    
    if (cnx != NULL) {
        PQfinish(cnx);
        if (config->debug)
            pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] connection closed - '%s:%d' for user '%s'", config->host, config->port, config->user);
    }
    
    if (config != NULL) {
        
        if (config->debug) {
            pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] erase config");
            pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] free config");
        }
            
        explicit_bzero(config, sizeof(Config));
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

    return check_auth(pamh, login, password, argc, argv);
}
