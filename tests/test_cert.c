/*
 * test_cert.c  --  pruebas de la verificacion de certificados.
 *
 * Los certificados se FABRICAN aqui mismo con la API de OpenSSL (CA, certificado
 * valido, caducado, de otro host...), asi no hay ficheros de prueba que
 * se puedan caducar con el tiempo.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../secure/cert_check.h"

static int g_checks = 0;
static int g_failed = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            fprintf(stderr, "    FALLO %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

static char g_dir[64];
static long g_serial = 1;

static void path_of(char *out, size_t n, const char *name)
{
    snprintf(out, n, "%s/%s", g_dir, name);
}

static int add_ext(X509 *x, X509V3_CTX *ctx, int nid, const char *value)
{
    X509_EXTENSION *e = X509V3_EXT_nconf_nid(NULL, ctx, nid, value);
    if (e == NULL)
        return 0;
    int ok = X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
    return ok;
}

/* Crea un certificado.
 *   issuer == NULL  -> autofirmado
 *   nb_off / na_off -> inicio / fin de validez, en segundos respecto a "ahora" */
static X509 *make_cert(EVP_PKEY *key, const char *cn, const char *san_dns,
                       X509 *issuer, EVP_PKEY *issuer_key,
                       long nb_off, long na_off, int is_ca)
{
    X509 *x = X509_new();
    if (x == NULL)
        return NULL;

    X509_set_version(x, 2);                                   /* X.509 v3 */
    ASN1_INTEGER_set(X509_get_serialNumber(x), g_serial++);
    X509_gmtime_adj(X509_getm_notBefore(x), nb_off);
    X509_gmtime_adj(X509_getm_notAfter(x), na_off);
    X509_set_pubkey(x, key);

    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : name);

    X509V3_CTX v3;
    X509V3_set_ctx(&v3, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
    if (is_ca) {
        add_ext(x, &v3, NID_basic_constraints, "critical,CA:TRUE");
        add_ext(x, &v3, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add_ext(x, &v3, NID_basic_constraints, "critical,CA:FALSE");
        add_ext(x, &v3, NID_key_usage, "critical,digitalSignature");
        add_ext(x, &v3, NID_ext_key_usage, "serverAuth");
        if (san_dns != NULL) {
            char san[160];
            snprintf(san, sizeof san, "DNS:%s", san_dns);
            add_ext(x, &v3, NID_subject_alt_name, san);
        }
    }

    if (X509_sign(x, issuer_key != NULL ? issuer_key : key, EVP_sha256()) == 0) {
        X509_free(x);
        return NULL;
    }
    return x;
}

static int save_pem(const char *path, X509 *x)
{
    BIO *b = BIO_new_file(path, "w");
    if (b == NULL)
        return 0;
    int ok = PEM_write_bio_X509(b, x);
    BIO_free(b);
    return ok;
}

#define DAY 86400L

int main(void)
{
    char tmpl[] = "/tmp/cert_test_XXXXXX";
    if (mkdtemp(tmpl) == NULL) {
        perror("mkdtemp");
        return 99;
    }
    snprintf(g_dir, sizeof g_dir, "%s", tmpl);

    /* Claves EC P-256 (rapidas de generar). */
    EVP_PKEY *ca_key = EVP_EC_gen("P-256");
    EVP_PKEY *ca2_key = EVP_EC_gen("P-256");
    EVP_PKEY *leaf_key = EVP_EC_gen("P-256");
    if (ca_key == NULL || ca2_key == NULL || leaf_key == NULL) {
        fprintf(stderr, "no se pudo generar claves\n");
        return 99;
    }

    X509 *ca       = make_cert(ca_key,  "CA de prueba 1", NULL, NULL, NULL, -DAY, 30 * DAY, 1);
    X509 *ca2      = make_cert(ca2_key, "CA de prueba 2", NULL, NULL, NULL, -DAY, 30 * DAY, 1);
    X509 *good     = make_cert(leaf_key, "server.test", "server.test", ca, ca_key, -DAY, 30 * DAY, 0);
    X509 *expired  = make_cert(leaf_key, "server.test", "server.test", ca, ca_key, -10 * DAY, -5 * DAY, 0);
    X509 *future   = make_cert(leaf_key, "server.test", "server.test", ca, ca_key, 5 * DAY, 10 * DAY, 0);
    X509 *selfsign = make_cert(leaf_key, "server.test", "server.test", NULL, NULL, -DAY, 30 * DAY, 0);
    CHECK(ca && ca2 && good && expired && future && selfsign);
    if (!(ca && ca2 && good && expired && future && selfsign))
        return 99;

    char p_ca[128], p_ca2[128], p_good[128], p_exp[128], p_fut[128], p_self[128], p_junk[128], p_none[128];
    path_of(p_ca, sizeof p_ca, "ca.pem");
    path_of(p_ca2, sizeof p_ca2, "ca2.pem");
    path_of(p_good, sizeof p_good, "good.pem");
    path_of(p_exp, sizeof p_exp, "expired.pem");
    path_of(p_fut, sizeof p_fut, "future.pem");
    path_of(p_self, sizeof p_self, "selfsigned.pem");
    path_of(p_junk, sizeof p_junk, "junk.pem");
    path_of(p_none, sizeof p_none, "no_existe.pem");

    CHECK(save_pem(p_ca, ca) && save_pem(p_ca2, ca2) && save_pem(p_good, good) &&
          save_pem(p_exp, expired) && save_pem(p_fut, future) && save_pem(p_self, selfsign));
    FILE *j = fopen(p_junk, "w");
    CHECK(j != NULL);
    if (j != NULL) {
        fputs("esto no es un certificado\n", j);
        fclose(j);
    }

    /* --- casos --- */
    struct {
        const char *name;
        cert_status got;
        cert_status want;
    } cases[] = {
        { "certificado valido",                  cert_verify_file(p_good, p_ca, "server.test"),  CERT_OK },
        { "host distinto (otra web)",            cert_verify_file(p_good, p_ca, "otro.test"),    CERT_ERR_HOSTNAME },
        { "caducado",                            cert_verify_file(p_exp,  p_ca, "server.test"),  CERT_ERR_EXPIRED },
        { "aun no valido (fecha futura)",        cert_verify_file(p_fut,  p_ca, "server.test"),  CERT_ERR_EXPIRED },
        { "firmado por OTRA CA",                 cert_verify_file(p_good, p_ca2, "server.test"), CERT_ERR_CHAIN },
        { "autofirmado que no esta en la CA",    cert_verify_file(p_self, p_ca, "server.test"),  CERT_ERR_CHAIN },
        { "fichero que no es un certificado",    cert_verify_file(p_junk, p_ca, "server.test"),  CERT_ERR_PARSE },
        { "certificado inexistente",             cert_verify_file(p_none, p_ca, "server.test"),  CERT_ERR_IO },
        { "CA inexistente",                      cert_verify_file(p_good, p_none, "server.test"), CERT_ERR_IO },
        { "CA que no es un certificado",         cert_verify_file(p_good, p_junk, "server.test"), CERT_ERR_IO },
        { "cert NULL",                           cert_verify_file(NULL, p_ca, "server.test"),    CERT_ERR_ARG },
        { "CA NULL",                             cert_verify_file(p_good, NULL, "server.test"),  CERT_ERR_ARG },
        { "host NULL",                           cert_verify_file(p_good, p_ca, NULL),           CERT_ERR_ARG },
        { "host vacio",                          cert_verify_file(p_good, p_ca, ""),             CERT_ERR_ARG },
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int bad = cases[i].got != cases[i].want;
        CHECK(!bad);    /* cuenta la comprobacion y, si falla, suma a g_failed */
        printf("[%s] %-38s -> %s\n", bad ? "FALLA" : " OK  ", cases[i].name, cert_strerror(cases[i].got));
    }

    X509_free(ca); X509_free(ca2); X509_free(good); X509_free(expired);
    X509_free(future); X509_free(selfsign);
    EVP_PKEY_free(ca_key); EVP_PKEY_free(ca2_key); EVP_PKEY_free(leaf_key);

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0)
        fprintf(stderr, "aviso: no se pudo borrar %s\n", g_dir);

    printf("\n%d comprobaciones, %d fallidas\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
