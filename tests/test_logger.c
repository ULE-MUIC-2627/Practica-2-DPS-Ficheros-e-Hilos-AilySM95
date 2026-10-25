/*
 * test_logger.c  --  pruebas del registro de auditoria (sin librerias externas).
 *
 * Compilar con sanitizers (ver Makefile):  make test   y   make test-tsan
 * Cada test crea su propio directorio temporal y lo borra al terminar.
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../secure/logger.h"

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

/* ----- utilidades ----------------------------------------------------- */

static char g_dir[64];

static void make_dir(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/al_test_XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        perror("mkdtemp");
        exit(99);
    }
}

static void path_of(char *out, size_t n, const char *name)
{
    snprintf(out, n, "%s/%s", g_dir, name);
}

static void remove_dir(void)
{
    char cmd[128];
    /* Solo borra nuestro directorio temporal recien creado. */
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0)
        fprintf(stderr, "aviso: no se pudo borrar %s\n", g_dir);
}

/* Lee un fichero entero (maximo 1 MiB) en un buffer reservado con malloc. */
static char *slurp(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;
    size_t cap = 1 << 20;
    char *buf = malloc(cap + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    buf[n] = '\0';
    if (len_out != NULL)
        *len_out = n;
    return buf;
}

static size_t count_lines(const char *s)
{
    size_t n = 0;
    for (; *s != '\0'; s++)
        if (*s == '\n')
            n++;
    return n;
}

/* ----- tests ---------------------------------------------------------- */

static void test_open_creates_file_0600(void)
{
    char p[128];
    path_of(p, sizeof p, "nuevo.log");
    audit_logger *lg = NULL;

    CHECK(al_open(&lg, p) == AL_OK);
    CHECK(lg != NULL);
    struct stat st;
    CHECK(stat(p, &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);       /* solo el dueno */
    CHECK(al_close(&lg) == AL_OK);
    CHECK(lg == NULL);                        /* al_close pone el puntero a NULL */
}

static void test_symlink_rejected(void)
{
    char real[128], link[128];
    path_of(real, sizeof real, "real.log");
    path_of(link, sizeof link, "enlace.log");
    FILE *f = fopen(real, "w");
    CHECK(f != NULL);
    if (f != NULL)
        fclose(f);
    CHECK(chmod(real, 0600) == 0);
    CHECK(symlink(real, link) == 0);

    audit_logger *lg = NULL;
    CHECK(al_open(&lg, link) == AL_ERR_OPEN);   /* O_NOFOLLOW */
    CHECK(lg == NULL);
}

static void test_loose_permissions_rejected(void)
{
    char p[128];
    path_of(p, sizeof p, "abierto.log");
    FILE *f = fopen(p, "w");
    CHECK(f != NULL);
    if (f != NULL)
        fclose(f);
    CHECK(chmod(p, 0666) == 0);                 /* cualquiera puede escribir */

    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_ERR_PERM);
    CHECK(lg == NULL);

    CHECK(chmod(p, 0640) == 0);                 /* grupo puede leer: tambien se rechaza */
    CHECK(al_open(&lg, p) == AL_ERR_PERM);

    CHECK(chmod(p, 0600) == 0);                 /* corregido: ahora si */
    CHECK(al_open(&lg, p) == AL_OK);
    CHECK(al_close(&lg) == AL_OK);
}

static void test_hardlink_rejected(void)
{
    char a[128], b[128];
    path_of(a, sizeof a, "orig.log");
    path_of(b, sizeof b, "duro.log");
    FILE *f = fopen(a, "w");
    CHECK(f != NULL);
    if (f != NULL)
        fclose(f);
    CHECK(chmod(a, 0600) == 0);
    CHECK(link(a, b) == 0);                     /* 2 nombres para el mismo fichero */

    audit_logger *lg = NULL;
    CHECK(al_open(&lg, a) == AL_ERR_PERM);      /* st_nlink != 1 */
    CHECK(lg == NULL);
}

static void test_non_regular_and_missing_rejected(void)
{
    audit_logger *lg = NULL;
    char p[128];

    CHECK(al_open(&lg, g_dir) == AL_ERR_OPEN);          /* es un directorio */
    CHECK(lg == NULL);

    path_of(p, sizeof p, "no/existe/aqui.log");
    CHECK(al_open(&lg, p) == AL_ERR_OPEN);              /* directorio inexistente */

    path_of(p, sizeof p, "tuberia");
    CHECK(mkfifo(p, 0600) == 0);
    CHECK(al_open(&lg, p) == AL_ERR_OPEN);              /* FIFO sin lector: no se cuelga */
    CHECK(lg == NULL);
}

static void test_null_and_bad_args(void)
{
    audit_logger *lg = NULL;
    char p[128];
    path_of(p, sizeof p, "args.log");

    CHECK(al_open(NULL, p) == AL_ERR_ARG);
    CHECK(al_open(&lg, NULL) == AL_ERR_ARG);
    CHECK(al_open(&lg, "") == AL_ERR_ARG);
    CHECK(al_write(NULL, "ana", "hola") == AL_ERR_ARG);
    CHECK(al_close(NULL) == AL_ERR_ARG);
    CHECK(al_new_session_id(NULL) == AL_ERR_ARG);

    CHECK(al_open(&lg, p) == AL_OK);
    CHECK(al_write(lg, NULL, "hola") == AL_ERR_ARG);
    CHECK(al_write(lg, "ana", NULL) == AL_ERR_ARG);
    CHECK(al_close(&lg) == AL_OK);
}

static void test_invalid_user_rejected(void)
{
    char p[128];
    path_of(p, sizeof p, "usuarios.log");
    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_OK);

    const char *bad[] = { "", "a b", "root\n", "../etc", "ana;rm", "a=b",
                          "123456789012345678901234567890123" /* 33 */ };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(al_write(lg, bad[i], "x") == AL_ERR_ARG);

    CHECK(al_write(lg, "ana_01.x-y", "ok") == AL_OK);
    CHECK(al_write(lg, "1234567890123456789012345678901" /* 31 */, "ok") == AL_OK);
    CHECK(al_close(&lg) == AL_OK);

    size_t len = 0;
    char *txt = slurp(p, &len);
    CHECK(txt != NULL);
    if (txt != NULL) {
        CHECK(count_lines(txt) == 2);           /* los rechazados NO escribieron nada */
        free(txt);
    }
}

static void test_log_injection_neutralized(void)
{
    char p[128];
    path_of(p, sizeof p, "inyeccion.log");
    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_OK);

    /* Intento de falsificar una segunda entrada del log. */
    CHECK(al_write(lg, "mallory",
                   "login ok\n2099-01-01T00:00:00Z seq=999 user=admin msg=acceso concedido") == AL_OK);
    CHECK(al_write(lg, "mallory", "\r\x1b[2J\ttabulador") == AL_OK);
    CHECK(al_close(&lg) == AL_OK);

    char *txt = slurp(p, NULL);
    CHECK(txt != NULL);
    if (txt != NULL) {
        CHECK(count_lines(txt) == 2);                    /* 2 escrituras = 2 lineas, no 3 */
        CHECK(strchr(txt, '\r') == NULL);
        CHECK(strchr(txt, '\x1b') == NULL);
        CHECK(strchr(txt, '\t') == NULL);
        free(txt);
    }
}

static void test_long_message_truncated(void)
{
    char p[128];
    path_of(p, sizeof p, "largo.log");
    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_OK);

    char *big = malloc(5001);
    CHECK(big != NULL);
    if (big == NULL)
        return;
    memset(big, 'A', 5000);
    big[5000] = '\0';
    CHECK(al_write(lg, "ana", big) == AL_OK);
    CHECK(al_close(&lg) == AL_OK);
    free(big);

    size_t len = 0;
    char *txt = slurp(p, &len);
    CHECK(txt != NULL);
    if (txt != NULL) {
        CHECK(len < 512);                                /* cabe en el buffer de linea */
        CHECK(count_lines(txt) == 1);
        CHECK(len >= 5 && memcmp(txt + len - 4, "...\n", 4) == 0);   /* marca de recorte */
        free(txt);
    }
}

static void test_double_close_is_safe(void)
{
    char p[128];
    path_of(p, sizeof p, "doble.log");
    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_OK);
    CHECK(al_close(&lg) == AL_OK);
    CHECK(al_close(&lg) == AL_ERR_ARG);                  /* 2.o cierre: error controlado */
    CHECK(al_write(lg, "ana", "tarde") == AL_ERR_ARG);   /* escribir tras cerrar: idem   */
}

static void test_write_error_is_reported(void)
{
    char p[128];
    path_of(p, sizeof p, "limite.log");
    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_OK);

    /* Limite de 100 bytes de tamano de fichero para simular "disco lleno".
     * SIGXFSZ se ignora para que write() devuelva EFBIG en vez de matar el proceso. */
    struct rlimit old, lim;
    CHECK(getrlimit(RLIMIT_FSIZE, &old) == 0);
    void (*old_handler)(int) = signal(SIGXFSZ, SIG_IGN);
    lim = old;
    lim.rlim_cur = 100;
    CHECK(setrlimit(RLIMIT_FSIZE, &lim) == 0);

    int ok = 0;
    al_status last = AL_OK;
    for (int i = 0; i < 6; i++) {
        last = al_write(lg, "ana", "mensaje de prueba");
        if (last != AL_OK)
            break;
        ok++;
    }
    CHECK(ok >= 1 && ok < 6);
    CHECK(last == AL_ERR_WRITE);                         /* el fallo NO se silencia */

    CHECK(setrlimit(RLIMIT_FSIZE, &old) == 0);
    signal(SIGXFSZ, old_handler);
    (void)al_close(&lg);
}

static void test_session_id(void)
{
    char a[AL_TOKEN_LEN + 1], b[AL_TOKEN_LEN + 1];
    CHECK(al_new_session_id(a) == AL_OK);
    CHECK(al_new_session_id(b) == AL_OK);
    CHECK(strlen(a) == AL_TOKEN_LEN);
    CHECK(strspn(a, "0123456789abcdef") == AL_TOKEN_LEN);
    CHECK(strcmp(a, b) != 0);                            /* 2^128 posibilidades */
}

/* --- concurrencia --- */
#define T_THREADS 8
#define T_WRITES  200

typedef struct {
    audit_logger *lg;
    int           id;
    al_status     result;
} t_ctx;

static void *t_worker(void *arg)
{
    t_ctx *c = arg;
    char user[16];
    snprintf(user, sizeof user, "hilo%d", c->id);
    c->result = AL_OK;
    for (int i = 0; i < T_WRITES && c->result == AL_OK; i++)
        c->result = al_write(c->lg, user, "mensaje concurrente");
    return NULL;
}

static void test_concurrent_writes(void)
{
    char p[128];
    path_of(p, sizeof p, "concurrente.log");
    audit_logger *lg = NULL;
    CHECK(al_open(&lg, p) == AL_OK);

    pthread_t th[T_THREADS];
    t_ctx ctx[T_THREADS];
    for (int i = 0; i < T_THREADS; i++) {
        ctx[i].lg = lg;
        ctx[i].id = i;
        CHECK(pthread_create(&th[i], NULL, t_worker, &ctx[i]) == 0);
    }
    for (int i = 0; i < T_THREADS; i++) {
        CHECK(pthread_join(th[i], NULL) == 0);
        CHECK(ctx[i].result == AL_OK);
    }
    CHECK(al_close(&lg) == AL_OK);

    char *txt = slurp(p, NULL);
    CHECK(txt != NULL);
    if (txt == NULL)
        return;
    CHECK(count_lines(txt) == (size_t)(T_THREADS * T_WRITES));

    /* Cada linea esta entera y bien formada, y 'seq' es 1,2,3,... sin huecos
     * ni repetidos (si hubiera una carrera de datos, saldrian repetidos). */
    unsigned long long expected = 1;
    int malformed = 0, out_of_order = 0;
    char *save = NULL;
    for (char *line = strtok_r(txt, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        unsigned long long seq = 0;
        char user[40], msg[64];
        if (sscanf(line, "%*s seq=%llu user=%39s msg=%63[^\n]", &seq, user, msg) != 3 ||
            strncmp(user, "hilo", 4) != 0 || strcmp(msg, "mensaje concurrente") != 0)
            malformed++;
        if (seq != expected)
            out_of_order++;
        expected++;
    }
    CHECK(malformed == 0);
    CHECK(out_of_order == 0);
    free(txt);
}

/* ----- ejecutor ------------------------------------------------------- */

typedef void (*test_fn)(void);

int main(void)
{
    (void)umask(077);   /* resultado reproducible aunque el usuario tenga otro umask */
    make_dir();

    struct { const char *name; test_fn fn; } tests[] = {
        { "open crea fichero con permisos 0600",        test_open_creates_file_0600 },
        { "enlace simbolico rechazado",                 test_symlink_rejected },
        { "permisos abiertos rechazados",               test_loose_permissions_rejected },
        { "enlace duro rechazado",                      test_hardlink_rejected },
        { "directorio/inexistente/FIFO rechazados",     test_non_regular_and_missing_rejected },
        { "argumentos NULL/vacios",                     test_null_and_bad_args },
        { "usuarios invalidos rechazados",              test_invalid_user_rejected },
        { "inyeccion en el log neutralizada",           test_log_injection_neutralized },
        { "mensaje largo recortado",                    test_long_message_truncated },
        { "doble cierre y uso tras cerrar",             test_double_close_is_safe },
        { "error de escritura se informa",              test_write_error_is_reported },
        { "id de sesion aleatorio",                     test_session_id },
        { "escrituras concurrentes (8 hilos x 200)",    test_concurrent_writes },
    };

    int failed_tests = 0;
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int before = g_failed;
        tests[i].fn();
        int bad = g_failed != before;
        printf("[%s] %s\n", bad ? "FALLA" : " OK  ", tests[i].name);
        failed_tests += bad;
    }

    remove_dir();
    printf("\n%d comprobaciones, %d fallidas, %d tests con fallo\n", g_checks, g_failed, failed_tests);
    return failed_tests == 0 ? 0 : 1;
}
