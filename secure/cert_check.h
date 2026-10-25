/*
 * cert_check.h  --  verificacion de un certificado X.509 con OpenSSL.
 *
 * Comprueba, TODAS a la vez:
 *   1. que el fichero se lee y es un PEM valido,
 *   2. que esta firmado por una CA en la que confiamos (cadena de confianza),
 *   3. que no ha caducado (ni es de fecha futura),
 *   4. que el nombre de host coincide con el del certificado (SAN/CN).
 */
#ifndef CERT_CHECK_H
#define CERT_CHECK_H

typedef enum {
    CERT_OK = 0,
    CERT_ERR_ARG,       /* argumento NULL o vacio                       */
    CERT_ERR_IO,        /* no se puede abrir/leer el certificado o la CA */
    CERT_ERR_PARSE,     /* el contenido no es un certificado PEM valido */
    CERT_ERR_CHAIN,     /* no firmado por la CA / cadena invalida       */
    CERT_ERR_EXPIRED,   /* caducado o todavia no valido                 */
    CERT_ERR_HOSTNAME,  /* el nombre de host no coincide                */
    CERT_ERR_INTERNAL   /* fallo interno de OpenSSL / memoria           */
} cert_status;

cert_status cert_verify_file(const char *cert_path,
                             const char *ca_path,
                             const char *hostname);

const char *cert_strerror(cert_status st);

#endif /* CERT_CHECK_H */
