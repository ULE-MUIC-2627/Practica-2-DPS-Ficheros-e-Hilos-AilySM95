/*
 * cert_check.c  --  ver cert_check.h
 *
 * Patron "goto done": una sola salida donde se libera TODO lo reservado,
 * pase lo que pase. En C es la forma habitual de evitar fugas de memoria
 * (CERT MEM31-C) cuando una funcion tiene muchos puntos de fallo.
 */
#include "cert_check.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

cert_status cert_verify_file(const char *cert_path,
                             const char *ca_path,
                             const char *hostname)
{
    if (cert_path == NULL || ca_path == NULL || hostname == NULL ||
        cert_path[0] == '\0' || ca_path[0] == '\0' || hostname[0] == '\0')
        return CERT_ERR_ARG;

    cert_status result = CERT_ERR_INTERNAL;
    BIO            *bio   = NULL;
    X509           *cert  = NULL;
    X509_STORE     *store = NULL;
    X509_STORE_CTX *ctx   = NULL;

    /* BIO_new_file abre el fichero; BIO_free lo cierra (siempre, en 'done'). */
    bio = BIO_new_file(cert_path, "r");
    if (bio == NULL) {
        result = CERT_ERR_IO;
        goto done;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        result = CERT_ERR_PARSE;
        goto done;
    }

    /* El "almacen de confianza" contiene SOLO la CA que nosotros indicamos. */
    store = X509_STORE_new();
    if (store == NULL)
        goto done;
    if (X509_STORE_load_file(store, ca_path) != 1) {
        result = CERT_ERR_IO;
        goto done;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL || X509_STORE_CTX_init(ctx, store, cert, NULL) != 1)
        goto done;

    /* [SEC] CWE-295: ademas de la cadena, se EXIGE que el nombre de host
     *       coincida, y que el certificado sirva para un servidor TLS.
     *       (Si se olvida esto, un certificado valido de OTRA web nos valdria.) */
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (X509_VERIFY_PARAM_set1_host(param, hostname, 0) != 1)
        goto done;
    if (X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER) != 1)
        goto done;

    /* [SEC] X509_verify_cert comprueba cadena, firmas y fechas (usa la hora
     *       actual). Devuelve 1 solo si TODO esta bien. */
    if (X509_verify_cert(ctx) == 1) {
        result = CERT_OK;
    } else {
        switch (X509_STORE_CTX_get_error(ctx)) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_CERT_NOT_YET_VALID:
            result = CERT_ERR_EXPIRED;
            break;
        case X509_V_ERR_HOSTNAME_MISMATCH:
            result = CERT_ERR_HOSTNAME;
            break;
        default:   /* cualquier otro motivo: lo tratamos como NO confiable */
            result = CERT_ERR_CHAIN;
            break;
        }
    }

done:
    /* Las funciones *_free aceptan NULL, asi que es seguro llamarlas todas. */
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    BIO_free(bio);
    return result;
}

const char *cert_strerror(cert_status st)
{
    switch (st) {
    case CERT_OK:           return "certificado valido";
    case CERT_ERR_ARG:      return "argumento invalido";
    case CERT_ERR_IO:       return "no se pudo leer el certificado o la CA";
    case CERT_ERR_PARSE:    return "el fichero no es un certificado PEM valido";
    case CERT_ERR_CHAIN:    return "no firmado por una CA de confianza / cadena invalida";
    case CERT_ERR_EXPIRED:  return "certificado caducado o aun no valido";
    case CERT_ERR_HOSTNAME: return "el nombre de host no coincide con el certificado";
    case CERT_ERR_INTERNAL: return "error interno";
    }
    return "estado desconocido";
}
