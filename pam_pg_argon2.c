#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <ctype.h>
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

/*
Structure du fichier ini par défaut :
host = 127.0.0.1
port = 5432
db_name = 
user = 
password = 
sslmode = false
debug = false
query = 
timeout = 3
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
static char *trim(const char *str) {

    if (!str) return NULL;

    // Supprime les espaces en début de chaine
    while (isspace((unsigned char)*str)) str++;

    // Chaine vide
    if (*str == '\0') return strdup(""); 

    // Supprime les espaces en fin de chaine
    const char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    size_t len = end - str + 1;

    // Alloue la mémoire pour la nouvelle chaîne (+1 pour le '\0')
    char *trimmed_str = malloc(len + 1);
    if (!trimmed_str) return NULL;

    // Copie le résultat et ajoute le caractère de fin
    memcpy(trimmed_str, str, len);
    trimmed_str[len] = '\0';

    return trimmed_str;
}

static int handler_config(void* config, const char* section, const char* name, const char* value) {

    ParseConfig* ctx = (ParseConfig*)config;
    Config* cfg = ctx->cfg;

    #define MATCH_SECTION(s) (strcasecmp(section, s) == 0)
    #define MATCH_KEY(n) (strcasecmp(name, n) == 0)

    // Nettoyer la valeur
    char *clean_value = trim(value);

    // Clef existant avec valeur nulle ou non def
    if (clean_value == NULL || clean_value[0] == '\0')  {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Null value for '%s.%s' key", section, name);
        return 0;
    }
   
    // Section [POSTGRES]
    if (MATCH_SECTION("POSTGRES")) {    

        if (MATCH_KEY("host")) {

            strncpy(cfg->host, clean_value, MAX_HOST_LEN - 1);
            cfg->host[MAX_HOST_LEN - 1] = '\0';
        
        } else if (MATCH_KEY("port")) {

            char *end;
            int port = (int)strtol(clean_value, &end, 10);

            // On n'a pas un entier
            if (*end != '\0') {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value not an integer for '%s.%s' key", section, name);
                return 0;
            }

            if (port >= 1 && port <= 65535) {
                cfg->port = (unsigned int)port;
            } else {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be [1-65535] for '%s.%s' key", section, name);
                return 0;
            }

        } else if (MATCH_KEY("db_name")) {

            strncpy(cfg->db_name, clean_value, MAX_DB_LEN - 1);
            cfg->db_name[MAX_DB_LEN - 1] = '\0';            
            
        } else if (MATCH_KEY("user")) {

            strncpy(cfg->user, clean_value, MAX_USER_LEN - 1);
            cfg->user[MAX_USER_LEN - 1] = '\0';  

        } else if (MATCH_KEY("password")) {

            strncpy(cfg->password, clean_value, MAX_PASS_LEN - 1);
            cfg->password[MAX_PASS_LEN - 1] = '\0'; 

        } else if (MATCH_KEY("sslmode")) {

            if (strncmp(clean_value, "true",4) == 0 || strncmp(clean_value, "false",5) == 0) {
                cfg->sslmode = parse_bool(clean_value);
            } else {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be 'true' or 'false' for '%s.%s' key", section, name);
                return 0;
            }

        } else if (MATCH_KEY("timeout")) {  
            
            char *end;
            int timeout = (int)strtol(clean_value, &end, 10);

            // On n'a pas un entier
            if (*end != '\0') {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value not an integer for '%s.%s' key", section, name);
                return 0;
            }

            if (timeout >= 0 && timeout <= 3600) {
                cfg->timeout = (unsigned int)timeout;
            } else {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be [0-3600] for '%s.%s' key", section, name);
                return 0;
            }

        } else {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Key '%s.%s' not exist", section, name);
            return 0;
        }
    }

    // Section [APP]
    else if (MATCH_SECTION("APP")) {

        if (MATCH_KEY("query")) {

            strncpy(cfg->query, clean_value, MAX_QUERY_LEN - 1);
            cfg->query[MAX_QUERY_LEN - 1] = '\0';

        } else if (MATCH_KEY("debug")) {

            if (strncmp(clean_value, "true",4) == 0 || strncmp(clean_value, "false",5) == 0) {
                cfg->debug = parse_bool(clean_value);
            } else {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Value must be 'true' or 'false' for '%s.%s' key", section, name);
                return 0;
            }

        } else {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Key '%s.%s' not exist", section, name);
            return 0;
        }

    } else {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Section '%s' not exist", section);
        return 0;
    }

    return 1; // Succes
}

/*
    Charger le fichier de configuration
    Retourner une structure en cas de succès, sinon NULL
*/
static Config* load_config(pam_handle_t *pamh, const char *fileName) {

    Config *config = malloc(sizeof(Config));
    if (config == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: memory allocation error to init configuration file '%s' : %m", fileName);
        return NULL;
    }

    // Déclacation de config avec les valeurs par défaut.
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
        .cfg = config
    };

    // Succès si status = 0
    int status = ini_parse(fileName, handler_config, &ctx);
    if (status > 0) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to load configuration file '%s' : %s\n", fileName, ctx.error_msg[0] != '\0' ? ctx.error_msg :"syntax error INI");
        return NULL;

    } else if (status == -1) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to load configuration file '%s'\n", fileName);
        return NULL;

    } else if (status < -1) {
        pam_syslog(pamh, LOG_ERR, "pam_pg_argon2: failed to load configuration file '%s' : memory allocation error\n", fileName);
        return NULL;
    }

    if (ctx.cfg->debug) {

        // Masquer le mot de passe pour le mode debug
        char masked_passwd[MAX_PASS_LEN];
        size_t len_passwd = strlen(ctx.cfg->password);
        for (size_t i = 0; i < len_passwd; i++) masked_passwd[i] = '*';
        masked_passwd[len_passwd] = '\0';

        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] configuration file '%s' loaded successfully\n", fileName);

        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] host    : %s\n", ctx.cfg->host);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] port    : %u\n", ctx.cfg->port);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] db_name : %s\n", ctx.cfg->db_name);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] user    : %s\n", ctx.cfg->user);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] password: %s\n", masked_passwd);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] timeout : %u\n", ctx.cfg->timeout);
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] sslmode : %s\n", ctx.cfg->sslmode?"true":"false");
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] debug   : %s\n", ctx.cfg->debug?"true":"false");
        pam_syslog(pamh, LOG_DEBUG, "pam_pg_argon2: [DEBUG] query   : %s\n", ctx.cfg->query);

    } else {
        pam_syslog(pamh, LOG_INFO, "pam_pg_argon2: configuration file '%s' loaded successfully\n", fileName);
    }

    return ctx.cfg;
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
