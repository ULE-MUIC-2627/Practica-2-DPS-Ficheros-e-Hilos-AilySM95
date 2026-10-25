/*
 * main.c  --  VERSION CORREGIDA del programa de ejemplo.
 *
 * Uso:  [AUDIT_LOG=ruta] ./secure <usuario> <num_hilos> <mensaje> [cert.pem ca.pem host]
 *
 *   - La ruta del log sale de la variable AUDIT_LOG (por defecto ./audit.log).
 *   - La clave de API sale de AUDIT_API_KEY: nunca esta en el codigo ni en el log.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "cert_check.h"
#include "logger.h"

#define MAX_THREADS 64
#define WRITES_PER_THREAD 3

/* Cada hilo recibe SU PROPIA estructura: no hay variables globales mutables.
 * [SEC] CERT CON43-C: evitar datos compartidos entre hilos sin proteccion. */
typedef struct {
    audit_logger *lg;       /* compartido, pero thread-safe por dentro */
    const char   *user;     /* solo lectura                            */
    const char   *msg;      /* solo lectura                            */
    al_status     result;   /* cada hilo escribe SOLO en el suyo       */
} worker_ctx;

static void *worker(void *arg)
{
    worker_ctx *c = arg;

    c->result = AL_OK;
    for (int i = 0; i < WRITES_PER_THREAD && c->result == AL_OK; i++)
        c->result = al_write(c->lg, c->user, c->msg);
    return NULL;                /* el hilo NO cierra el log: eso lo hace main */
}

/* Convierte texto a entero validando todo.
 * [SEC] CERT ERR34-C: atoi() no distingue "0" de "basura" ni detecta desbordes. */
static int parse_threads(const char *s, int *out)
{
    char *end = NULL;

    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > MAX_THREADS)
        return -1;
    *out = (int)v;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 7) {
        fprintf(stderr,
                "uso: %s <usuario> <num_hilos 1..%d> <mensaje> [cert.pem ca.pem host]\n",
                argv[0], MAX_THREADS);
        return 2;
    }

    int nthreads;
    if (parse_threads(argv[2], &nthreads) != 0) {
        fprintf(stderr, "error: num_hilos debe ser un entero entre 1 y %d\n", MAX_THREADS);
        return 2;
    }

    const char *path = getenv("AUDIT_LOG");
    if (path == NULL || path[0] == '\0')
        path = "audit.log";

    int exit_code = 0;
    audit_logger *lg = NULL;
    al_status st = al_open(&lg, path);
    if (st != AL_OK) {
        fprintf(stderr, "error: al_open('%s'): %s\n", path, al_strerror(st));
        return 1;
    }

    /* Id de sesion criptograficamente seguro. */
    char sid[AL_TOKEN_LEN + 1];
    char text[AL_MSG_MAX];
    st = al_new_session_id(sid);
    if (st == AL_OK) {
        /* La clave de API (si existe) se usaria para autenticarse; JAMAS se
         * imprime ni se registra. [SEC] CWE-532 / CERT MSC41-C. */
        const char *key = getenv("AUDIT_API_KEY");
        int n = snprintf(text, sizeof text, "sesion=%s api_key=%s", sid,
                         key != NULL ? "configurada" : "no-configurada");
        if (n > 0 && (size_t)n < sizeof text)
            st = al_write(lg, "system", text);
        else
            st = AL_ERR_INTERNAL;
    }
    if (st != AL_OK) {
        fprintf(stderr, "error: %s\n", al_strerror(st));
        exit_code = 1;
        goto cleanup_log;
    }

    /* calloc(n, size) comprueba el desbordamiento de n*size y pone todo a 0.
     * [SEC] CERT MEM07-C / INT30-C. */
    pthread_t  *th  = calloc((size_t)nthreads, sizeof *th);
    worker_ctx *ctx = calloc((size_t)nthreads, sizeof *ctx);
    if (th == NULL || ctx == NULL) {
        fprintf(stderr, "error: sin memoria\n");
        exit_code = 1;
        free(th);
        free(ctx);
        goto cleanup_log;
    }

    int created = 0;
    for (int i = 0; i < nthreads; i++) {
        ctx[i].lg = lg;
        ctx[i].user = argv[1];
        ctx[i].msg = argv[3];
        /* [SEC] CERT POS54-C: pthread_create DEVUELVE el error (no usa errno). */
        int rc = pthread_create(&th[i], NULL, worker, &ctx[i]);
        if (rc != 0) {
            fprintf(stderr, "error: pthread_create fallo (codigo %d)\n", rc);
            exit_code = 1;
            break;
        }
        created++;
    }

    /* Se espera SOLO a los hilos que se crearon, y a TODOS antes de cerrar. */
    for (int i = 0; i < created; i++) {
        int rc = pthread_join(th[i], NULL);
        if (rc != 0) {
            fprintf(stderr, "error: pthread_join fallo (codigo %d)\n", rc);
            exit_code = 1;
        } else if (ctx[i].result != AL_OK) {
            fprintf(stderr, "error: hilo %d: %s\n", i, al_strerror(ctx[i].result));
            exit_code = 1;
        }
    }
    free(th);
    free(ctx);

    /* Verificacion de certificado (opcional). */
    if (exit_code == 0 && argc == 7) {
        cert_status cs = cert_verify_file(argv[4], argv[5], argv[6]);
        printf("certificado: %s\n", cert_strerror(cs));
        if (cs != CERT_OK)
            exit_code = 3;
    }

cleanup_log:
    st = al_close(&lg);         /* un unico cierre, con el resultado comprobado */
    if (st != AL_OK) {
        fprintf(stderr, "error: al_close: %s\n", al_strerror(st));
        exit_code = 1;
    }
    return exit_code;
}
