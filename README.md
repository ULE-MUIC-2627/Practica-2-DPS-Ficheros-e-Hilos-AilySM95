# Ejemplo de seguridad en C: ficheros, certificados e hilos

Registro de auditoría en C (`secure/`) escrito para evitar errores típicos de seguridad:

- **Ficheros:** apertura atómica sin TOCTOU, rechazo de enlaces simbólicos, permisos `0600`, un solo cierre con comprobación de errores.
- **Certificados:** verificación X.509 con OpenSSL (cadena de confianza, caducidad y nombre de host).
- **Hilos:** escritura concurrente protegida con un mutex, sin datos globales compartidos.

Cada decisión de seguridad se relaciona con una regla de SEI CERT C o un CWE. La explicación completa, con la tabla de los 15 errores que se evitan, está en [DOCUMENTACION.md](DOCUMENTACION.md).

## Estructura

```
secure/               código (logger, cert_check, main)
tests/                tests del logger y de certificados
Makefile              compilación, tests y sanitizers
DOCUMENTACION.md      explicación detallada y resultados
```

## Requisitos

Linux (o WSL), `gcc`, `make` y las cabeceras de OpenSSL.

```bash
sudo apt install gcc make libssl-dev
```

## Uso

```bash
make check     # tests con AddressSanitizer + UBSan y ThreadSanitizer
make           # compila bin/secure

# <usuario> <num_hilos 1..64> <mensaje>
AUDIT_LOG=./mi.log ./bin/secure ana 4 "hola mundo"
```

Estándar: C11. Con GCC 13 también compila con `make STD=-std=c2x`.

## Resultados verificados

- 13 tests del logger y 14 casos de certificados, todos correctos, con AddressSanitizer, UBSan y ThreadSanitizer.
- Los tests se comprobaron con mutaciones: al quitar el mutex, la sanitización, `O_NOFOLLOW` o la comprobación del host, fallan.
- Sin errores ni fugas bajo valgrind.
- Un enlace simbólico apuntando a otro fichero se rechaza y el fichero destino queda intacto.

## Limitaciones

No se cubre: symlinks en directorios intermedios de la ruta, revocación de certificados (CRL/OCSP), integridad del log frente a quien tenga permisos del mismo usuario, fuzzing ni cobertura de código. Detalle en la sección 8 de `DOCUMENTACION.md`.

## Uso de Inteligencia Artificial

- **Herramienta:** Claude (Anthropic).
- **Tareas:** generación del código de ejemplo, los tests, el Makefile y la documentación.
- **Verificación:** compilación y ejecución real de los tests, de los sanitizers y de la prueba de symlink, y mutaciones manuales para comprobar que los tests detectan los fallos.
- **Ejemplo:** - **Ejemplo:** Para comprobar que los tests detectan de verdad los fallos y no pasan "porque sí", rompí el código a propósito en copias del proyecto y ejecuté los tests en mi máquina: (1) quitar el mutex de `al_write` hizo que ThreadSanitizer avisara de `data race` y fallara el test de 8 hilos; (2) quitar `O_NOFOLLOW` hizo fallar el test del enlace simbólico; (3) quitar la limpieza de caracteres de control hizo fallar el test de inyección en el log (4 comprobaciones); (4) quitar la comprobación del nombre de host hizo que un certificado de otra web se aceptara como válido. Los tests fallaron en los cuatro casos. Después borré las copias y comprobé que en el proyecto original `make check` volvía a dar 0 fallidas.
- **Tiempo invertido:** 4 Horas
