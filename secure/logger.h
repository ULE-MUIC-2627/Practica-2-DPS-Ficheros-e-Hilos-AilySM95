/*
 * logger.h  --  Registro de auditoria seguro y thread-safe.
 *
 * Reglas de uso (el "contrato"):
 *   - al_open() devuelve un logger; al_close() lo cierra y lo libera.
 *   - Varios hilos pueden llamar a al_write() a la vez con el mismo logger.
 *   - al_close() NO puede llamarse mientras otro hilo esta dentro de al_write():
 *     primero hay que esperar (pthread_join) a que todos los hilos terminen.
 *   - Todas las funciones devuelven un al_status: SIEMPRE hay que comprobarlo.
 */
#ifndef AUDIT_LOGGER_H
#define AUDIT_LOGGER_H

#include <stddef.h>

typedef struct audit_logger audit_logger;   /* tipo opaco: el contenido es privado */

typedef enum {
    AL_OK = 0,
    AL_ERR_ARG,     /* argumento invalido (NULL, usuario con caracteres raros...) */
    AL_ERR_OPEN,    /* no se pudo abrir (no existe, es un enlace simbolico...)     */
    AL_ERR_PERM,    /* el fichero existe pero NO es seguro (permisos, dueno...)    */
    AL_ERR_WRITE,   /* fallo al escribir (disco lleno, I/O...)                     */
    AL_ERR_CLOSE,   /* fallo al cerrar (puede significar datos perdidos)           */
    AL_ERR_NOMEM,   /* sin memoria                                                 */
    AL_ERR_INTERNAL /* fallo inesperado (mutex, reloj...)                          */
} al_status;

#define AL_USER_MAX 31      /* longitud maxima de un usuario              */
#define AL_MSG_MAX  256     /* mensajes mas largos se recortan            */
#define AL_TOKEN_LEN 32     /* caracteres hex de un id de sesion (sin \0) */

/* Abre (o crea con permisos 0600) el fichero de log para anadir al final. */
al_status al_open(audit_logger **out, const char *path);

/* Escribe una linea: "<fecha UTC> seq=<n> user=<u> msg=<m>\n". Thread-safe. */
al_status al_write(audit_logger *lg, const char *user, const char *msg);

/* Cierra, libera y pone *lg = NULL. Llamarlo dos veces es seguro. */
al_status al_close(audit_logger **lg);

/* Id de sesion aleatorio criptograficamente seguro: 32 hex + '\0' (33 bytes). */
al_status al_new_session_id(char out[AL_TOKEN_LEN + 1]);

/* Texto legible para un codigo de estado. */
const char *al_strerror(al_status st);

#endif /* AUDIT_LOGGER_H */
