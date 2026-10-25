/*
 * logger.c  --  implementacion del registro de auditoria seguro.
 * Cada decision de seguridad lleva un comentario  [SEC] ...  con la regla
 * de SEI CERT C / CWE que resuelve. Ver DOCUMENTACION.md.
 */
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Estructura PRIVADA: quien use la libreria solo ve un puntero opaco. */
struct audit_logger {
    int             fd;     /* descriptor del fichero abierto            */
    pthread_mutex_t lock;   /* [SEC] protege 'seq' y el orden de escritura */
    uint64_t        seq;    /* numero de linea; solo se toca con el lock */
};

/* ------------------------------------------------------------------ */
/* Funciones auxiliares (privadas: 'static')                           */
/* ------------------------------------------------------------------ */

/* Escribe TODOS los bytes. write() puede escribir menos de lo pedido o ser
 * interrumpido por una senal (EINTR): hay que repetir.
 * [SEC] CERT ERR33-C / FIO: comprobar el resultado de cada llamada de E/S. */
static al_status write_all(int fd, const char *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t w = write(fd, buf + done, len - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return AL_ERR_WRITE;
        }
        if (w == 0)                 /* evita un bucle infinito */
            return AL_ERR_WRITE;
        done += (size_t)w;
    }
    return AL_OK;
}

/* Usuario valido: 1..AL_USER_MAX caracteres de [A-Za-z0-9_.-].
 * [SEC] Lista BLANCA (solo se permite lo conocido) en vez de lista negra.
 * strnlen limita la lectura aunque la cadena no estuviera terminada. */
static int valid_user(const char *user)
{
    size_t len = strnlen(user, AL_USER_MAX + 1);

    if (len == 0 || len > AL_USER_MAX)
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)user[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok)
            return 0;
    }
    return 1;
}

/* Copia como mucho 'maxlen' bytes de src a dst, cambiando los caracteres de
 * control (\n, \r, \t, ESC...) por '?'. Si recorta, anade "...".
 * dst debe tener sitio para maxlen + 3 + 1 bytes.
 * [SEC] CWE-117 (log injection): sin esto, el mensaje "ok\n2026... user=root"
 * crearia una linea falsa en el log. */
static size_t sanitize_copy(char *dst, const char *src, size_t maxlen)
{
    size_t i = 0;

    for (; i < maxlen && src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        char out = (char)c;
        if (c < 0x20 || c == 0x7f)
            out = '?';
        dst[i] = out;
    }
    size_t n = i;
    if (i == maxlen && src[i] != '\0') {     /* habia mas texto: recortado */
        memcpy(dst + n, "...", 3);
        n += 3;
    }
    dst[n] = '\0';
    return n;
}

/* ------------------------------------------------------------------ */
/* API publica                                                          */
/* ------------------------------------------------------------------ */

al_status al_open(audit_logger **out, const char *path)
{
    if (out == NULL)
        return AL_ERR_ARG;
    *out = NULL;                              /* estado definido si falla */
    if (path == NULL || path[0] == '\0')
        return AL_ERR_ARG;

    /* [SEC] CERT FIO45-C (TOCTOU): NO se usa access() antes de abrir. Se abre
     *       directamente y se mira el resultado: una sola operacion atomica.
     * [SEC] O_NOFOLLOW: si la ruta final es un enlace simbolico, falla (ELOOP).
     * [SEC] O_CREAT con modo 0600: si se crea, solo el dueno puede leer/escribir.
     * [SEC] O_APPEND: cada write() va al final, sin pisar lo anterior.
     * [SEC] O_CLOEXEC: el descriptor no se hereda al ejecutar otros programas.
     * [SEC] O_NONBLOCK: abrir una FIFO sin lector no deja el programa colgado. */
    int fd = open(path,
                  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                  0600);
    if (fd < 0)
        return AL_ERR_OPEN;

    /* [SEC] Se inspecciona el fichero YA ABIERTO (fstat sobre el fd, no sobre
     *       el nombre): asi nadie puede cambiarlo "por debajo" entre medias. */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        (void)close(fd);
        return AL_ERR_OPEN;
    }
    if (!S_ISREG(st.st_mode) ||                 /* solo ficheros normales      */
        st.st_uid != geteuid() ||               /* debe ser nuestro            */
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 || /* sin acceso a grupo/otros */
        st.st_nlink != 1) {                     /* sin enlaces duros extra     */
        (void)close(fd);
        return AL_ERR_PERM;
    }

    audit_logger *lg = calloc(1, sizeof *lg);   /* calloc: todo a cero */
    if (lg == NULL) {
        (void)close(fd);
        return AL_ERR_NOMEM;
    }
    if (pthread_mutex_init(&lg->lock, NULL) != 0) {
        free(lg);
        (void)close(fd);
        return AL_ERR_INTERNAL;
    }
    lg->fd = fd;
    lg->seq = 0;
    *out = lg;
    return AL_OK;
}

al_status al_write(audit_logger *lg, const char *user, const char *msg)
{
    /* [SEC] CERT API00-C: validar TODOS los argumentos antes de usarlos. */
    if (lg == NULL || user == NULL || msg == NULL)
        return AL_ERR_ARG;
    if (!valid_user(user))
        return AL_ERR_ARG;

    /* Todo lo que se prepara aqui son variables LOCALES (en la pila de este
     * hilo): no se comparten con otros hilos, asi que no necesitan candado.
     * [SEC] Un buffer global compartido entre hilos seria una carrera de datos. */
    char clean[AL_MSG_MAX + 4];
    sanitize_copy(clean, msg, AL_MSG_MAX);

    time_t now = time(NULL);
    struct tm tmv;
    char ts[32];
    if (now == (time_t)-1 || gmtime_r(&now, &tmv) == NULL ||   /* gmtime_r: thread-safe */
        strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0)
        return AL_ERR_INTERNAL;

    /* [SEC] CERT CON43-C: el estado compartido (seq y el fichero)
     *       solo se toca con el mutex cogido. */
    if (pthread_mutex_lock(&lg->lock) != 0)
        return AL_ERR_INTERNAL;

    lg->seq++;
    char line[512];
    /* [SEC] CERT FIO30-C: el formato es una CONSTANTE; los datos del usuario
     *       solo van como argumentos (%s), nunca como formato.
     * [SEC] snprintf nunca escribe mas de sizeof line bytes. */
    int len = snprintf(line, sizeof line, "%s seq=%llu user=%s msg=%s\n",
                       ts, (unsigned long long)lg->seq, user, clean);
    al_status st = AL_OK;
    if (len < 0 || (size_t)len >= sizeof line)   /* error o recorte */
        st = AL_ERR_INTERNAL;
    else
        st = write_all(lg->fd, line, (size_t)len);

    if (pthread_mutex_unlock(&lg->lock) != 0 && st == AL_OK)
        st = AL_ERR_INTERNAL;
    return st;
}

al_status al_close(audit_logger **lgp)
{
    /* [SEC] CERT FIO46-C / MEM30-C: tras cerrar, el puntero del llamador pasa
     *       a NULL, asi un segundo al_close() o un al_write() tardio fallan de
     *       forma controlada (AL_ERR_ARG) en vez de usar memoria liberada. */
    if (lgp == NULL || *lgp == NULL)
        return AL_ERR_ARG;

    audit_logger *lg = *lgp;
    *lgp = NULL;

    al_status st = AL_OK;
    /* [SEC] CERT ERR33-C: close() puede fallar y significar datos perdidos
     *       (por ejemplo, disco lleno). fsync fuerza que lleguen al disco. */
    if (fsync(lg->fd) != 0 && errno != EINVAL && errno != EROFS)
        st = AL_ERR_CLOSE;
    if (close(lg->fd) != 0)         /* si falla, NO se reintenta (fd ya invalido en Linux) */
        st = AL_ERR_CLOSE;

    (void)pthread_mutex_destroy(&lg->lock);
    free(lg);
    return st;
}

al_status al_new_session_id(char out[AL_TOKEN_LEN + 1])
{
    if (out == NULL)
        return AL_ERR_ARG;

    /* [SEC] CERT MSC30-C: rand() es predecible. getrandom() usa el generador
     *       criptografico del kernel. */
    unsigned char raw[AL_TOKEN_LEN / 2];
    size_t got = 0;
    while (got < sizeof raw) {
        ssize_t r = getrandom(raw + got, sizeof raw - got, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return AL_ERR_INTERNAL;
        }
        got += (size_t)r;
    }

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof raw; i++) {
        out[2 * i]     = hex[raw[i] >> 4];
        out[2 * i + 1] = hex[raw[i] & 0x0F];
    }
    out[AL_TOKEN_LEN] = '\0';
    explicit_bzero(raw, sizeof raw);   /* [SEC] borra el material aleatorio de la pila */
    return AL_OK;
}

const char *al_strerror(al_status st)
{
    switch (st) {
    case AL_OK:           return "correcto";
    case AL_ERR_ARG:      return "argumento invalido";
    case AL_ERR_OPEN:     return "no se pudo abrir el fichero (no existe, enlace simbolico, directorio...)";
    case AL_ERR_PERM:     return "fichero inseguro (permisos, dueno o enlaces duros)";
    case AL_ERR_WRITE:    return "error de escritura";
    case AL_ERR_CLOSE:    return "error al cerrar/sincronizar (posible perdida de datos)";
    case AL_ERR_NOMEM:    return "sin memoria";
    case AL_ERR_INTERNAL: return "error interno";
    }
    return "estado desconocido";
}
