# Ejemplo de seguridad en C: ficheros, certificados e hilos

Programa de ejemplo en C (`secure/`): un registro de auditoría que varios hilos escriben en un fichero, con verificación de certificados X.509. Está escrito para **evitar 15 errores típicos** de seguridad, cada uno explicado y ligado a una regla de **SEI CERT C** o a un **CWE**, y comprobado con tests y herramientas reales. Todo lo que aparece como "resultado" en este documento sale de ejecuciones reales hechas al crear el proyecto.

---

## 1. Qué hay en la carpeta

```
ejemplo_c_seguridad/
├── secure/
│   ├── logger.h / .c     Registro de auditoría seguro y thread-safe (abrir/escribir/cerrar)
│   ├── cert_check.h / .c Verificación de certificados X.509 con OpenSSL
│   └── main.c            Programa corregido (hilos, argumentos, orden de cierre)
├── tests/
│   ├── test_logger.c     13 tests del logger (116 comprobaciones)
│   └── test_cert.c       14 casos de certificados (17 comprobaciones)
├── Makefile              Compilación, tests y sanitizers
├── README.md             Resumen y uso rápido
├── .gitignore            Excluye binarios, logs y claves de prueba
└── DOCUMENTACION.md      Este documento
```

### Cómo ejecutarlo

Necesitas `gcc`, `make` y las cabeceras de OpenSSL (`libssl-dev` en Debian/Ubuntu).

```bash
make                  # compila bin/secure
make test             # tests con AddressSanitizer + UBSan
make test-tsan        # test de concurrencia con ThreadSanitizer
make check            # los dos anteriores

# Versión segura:
AUDIT_LOG=./mi.log AUDIT_API_KEY=lo-que-sea ./bin/secure ana 4 "hola mundo"
# Con comprobación de certificado:
./bin/secure ana 2 "hola" cert.pem ca.pem server.test
```

Estándar de C: el proyecto usa **C11**. Con GCC 13 funciona también `make STD=-std=c2x` (comprobado); con GCC 14 o posterior, `make STD=-std=c23`.

### Pruebas manuales (reproducibles)

Además de `make check`, estas pruebas se pueden repetir a mano desde la carpeta del proyecto, tras `make`.

**Ejecución normal.** Debe dar 13 líneas (1 de sesión + 4 hilos × 3), `seq` de 1 a 13 y permisos `-rw-------`:

```bash
rm -f mi.log
AUDIT_LOG=./mi.log ./bin/secure ana 4 "hola mundo"
cat mi.log; ls -l mi.log
```

**Enlace simbólico.** Debe fallar con `error: al_open(...)` y dejar `victima.txt` intacto:

```bash
echo "dato importante" > victima.txt
ln -s victima.txt enlace.log
AUDIT_LOG=./enlace.log ./bin/secure ana 2 hola; echo "exit=$?"
cat victima.txt
```

**Argumentos inválidos.** Los dos primeros devuelven 2; el tercero devuelve 1 (usuario con caracteres no permitidos):

```bash
./bin/secure ana abc hola; echo "exit=$?"
./bin/secure ana 65 hola; echo "exit=$?"
./bin/secure "ana;rm" 2 hola; echo "exit=$?"
```

**Certificados.** Se crea una CA y un certificado para `server.test` con la herramienta `openssl`:

```bash
mkdir certs && cd certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.pem -days 30 -subj "/CN=CA de prueba" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout server.key -out server.csr -subj "/CN=server.test"
printf "subjectAltName=DNS:server.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 30 -extfile ext.cnf
cd ..
```

Resultados esperados (comprobados):

| Comando | Mensaje | Salida |
|---|---|---|
| `AUDIT_LOG=./c.log ./bin/secure ana 1 hola certs/server.pem certs/ca.pem server.test` | `certificado valido` | 0 |
| igual, con host `otra.web` | `el nombre de host no coincide con el certificado` | 3 |
| con otra CA (`otra_ca.pem`) | `no firmado por una CA de confianza / cadena invalida` | 3 |

La carpeta `certs/` contiene claves privadas: está en el `.gitignore` y **no debe subirse**.

---

## 2. Mini-curso: lo que necesitas saber de C para entender el código

**Programa y `main`.** Un programa en C empieza en la función `main`. Las líneas `#include <...>` traen "cajas de herramientas" (`stdio.h` para imprimir, `string.h` para texto, `pthread.h` para hilos...).

**Un texto (string) es un array de caracteres que termina en `\0`.** `"hola"` ocupa **5** bytes: `h o l a \0`. C **no sabe** cuánto mide un array: si copias 20 letras a un hueco de 16, C las escribe igualmente y **pisa lo que haya detrás**. Eso es un *desbordamiento de buffer* (R-05).

**Puntero.** Es una variable que guarda *la dirección* de otra cosa en memoria. `NULL` significa "no apunta a nada". Usar un puntero `NULL` revienta el programa; por eso hay que comprobarlo (R-03).

**Pila y montón.** Las variables locales (`char username[16]`) viven en la **pila** y desaparecen al salir de la función. Lo que pides con `malloc` vive en el **montón** y **tú** debes devolverlo con `free`. Olvidarlo es una *fuga* (R-07); liberarlo dos veces es un *doble free* (R-07).

**Fichero.** Hay dos formas de abrir uno:
- `fopen`/`fclose`: trabajan con un `FILE *` (cómodo, con buffer interno).
- `open`/`close`: trabajan con un número entero, el *descriptor de fichero* (`fd`). Da más control de seguridad (banderas como `O_NOFOLLOW`, permisos al crear, `fstat` sobre el fichero ya abierto). El logger seguro usa esta.

Regla de oro: **todo lo que se abre se cierra una vez, y solo una**, y **se comprueba el resultado**.

**Hilo (thread).** Un hilo es "otro trabajador" dentro del mismo programa. Todos ven las **mismas variables globales**. Si dos hilos tocan la misma variable a la vez y al menos uno escribe, hay una *carrera de datos* (R-09). Un **mutex** es un candado: solo un hilo a la vez puede tener cogido el candado; los demás esperan.

**Comportamiento indefinido (UB).** En C, algunos errores (desbordar un array, usar memoria liberada, carrera de datos) no dan "error": el estándar dice que **cualquier cosa puede pasar** (funcionar "bien" en tu prueba y fallar en producción, o ser explotable). Por eso se usan *sanitizers*, que detectan estos errores mientras ejecutas.

---

## 3. Qué hace el programa

Es un **registro de auditoría**: varios hilos escriben líneas en un fichero de log, y opcionalmente se comprueba un certificado.

```
 argumentos  ──►  abrir log  ──►  anotar inicio (sesión)  ──►  lanzar N hilos
                                                                   │  cada uno escribe 3 líneas
                                                                   ▼
        cerrar log  ◄──  (opcional) comprobar certificado  ◄──  esperar a todos (join)
```

Formato de línea en la versión segura:

```
2026-10-22T22:06:57Z seq=2 user=ana msg=hola
```

---

## 4. Los 15 errores típicos que evita el código

Se describen como los cometería una implementación ingenua. Leyenda: **CERT** = regla de SEI CERT C; **CWE** = catálogo de debilidades (cwe.mitre.org).

| ID | Error típico (a evitar) | Por qué es grave | Regla | Cómo se evita en `secure/` |
|---|---|---|---|---|
| **R-01** | Una clave de API escrita en el código fuente | Acaba en git, en el binario (`strings`) y en capturas | CERT MSC41-C, CWE-798 | Se lee de la variable de entorno `AUDIT_API_KEY`; nunca se imprime |
| **R-02** | Ruta fija `/tmp/audit.log` + `access()` y luego `fopen()` | Otro usuario puede crear un **enlace simbólico** antes del `fopen` y hacer que escribas (y cambies permisos) en un fichero ajeno. Entre el *check* y el *use* hay una ventana: **TOCTOU** | CERT FIO45-C, FIO21-C, CWE-367, CWE-377 | Ruta configurable; **sin `access()`**: se abre directamente con `O_NOFOLLOW`; luego `fstat` sobre el fd |
| **R-03** | `fopen` sin comprobar `NULL` (log y certificado) | Si falla (sin permiso, disco...), el siguiente uso revienta | CERT ERR33-C, EXP34-C, CWE-476 | Se comprueba `open() < 0` y se devuelve un código de error |
| **R-04** | `chmod(LOG_PATH, 0666)` | Cualquiera puede leer **y modificar** el log de auditoría | CERT FIO06-C, CWE-732 | Se crea con `0600`; si ya existe con permisos de grupo/otros, **se rechaza** (`AL_ERR_PERM`) |
| **R-05** | `strcpy` a un array pequeño (`char user[16]`); `strcat` a un buffer fijo | Desbordamiento de buffer: corrupción de memoria, posible ejecución de código | CERT STR31-C, CWE-120/787 | `snprintf` con tamaño; validación de longitud; `sanitize_copy` con límite |
| **R-06** | `fprintf(f, texto_del_usuario)`: el texto del usuario es el **formato** | Con `%s%s%s` se leen direcciones de memoria y se cae; con `%n` se puede escribir en memoria | CERT FIO30-C, CWE-134 | Formato **constante**: `"%s seq=%llu user=%s msg=%s\n"`; los datos solo van como argumentos |
| **R-07** | Cada hilo cierra el fichero y `main` lo vuelve a cerrar; memoria sin `free`; el certificado nunca se cierra ni se libera | Cierre múltiple = **doble free**; los demás hilos usan un fichero ya cerrado (*use-after-free*); fugas de memoria y descriptores | CERT FIO42-C, FIO46-C, MEM30-C, MEM31-C, CWE-415/416/772 | **Un solo cierre**, en `main`, tras el `join`; `al_close(&lg)` pone el puntero a `NULL`; patrón `goto done` en el certificado |
| **R-08** | No se mira el resultado de `fprintf`, `fclose`, `chmod`... | Se pierden datos sin enterarse (disco lleno) | CERT ERR33-C, CWE-252 | `write_all` repite escrituras parciales y detecta errores; `al_close` comprueba `fsync` y `close` |
| **R-09** | Contador y buffer globales compartidos entre hilos, sin candado | **Carrera de datos**: números repetidos, líneas mezcladas, UB | CERT CON43-C, CWE-362 | Buffers **locales**; contador y escritura bajo un **mutex** |
| **R-10** | `srand(time(NULL))` + `rand()` para el "token" | Predecible: quien conozca la hora aproximada reproduce el token | CERT MSC30-C, MSC32-C, CWE-338 | `getrandom()` del kernel; 128 bits; se borra el material de la pila |
| **R-11** | "Validar" un certificado solo comprobando que el fichero se **lea** | Acepta certificados falsos, caducados o de otra web | CWE-295, CWE-297 | `cert_verify_file`: cadena + caducidad + nombre de host + uso "servidor TLS" |
| **R-12** | `atoi` y `malloc(n * sizeof ...)` sin validar | `"abc"` da 0 sin avisar; `-5` o números enormes dan tamaños absurdos; 100 000 hilos agotan recursos | CERT ERR34-C, INT30-C, INT31-C, CWE-190, CWE-770 | `strtol` con comprobación de `errno`/`endptr`; rango 1..64; `calloc(n, size)` (detecta desbordes) |
| **R-13** | `pthread_create` sin comprobar | Si falla, el `join` posterior usa un hilo inexistente | CERT POS54-C | Se comprueba, se cuentan los hilos creados y se espera **solo** a esos |
| **R-14** | El usuario/mensaje puede contener `\n` | **Inyección en el log**: se falsifican entradas (p. ej. "admin acceso concedido") | CWE-117 | Usuario por lista blanca `[A-Za-z0-9_.-]`; los caracteres de control del mensaje se cambian por `?` |
| **R-15** | Escribir la clave de API en el propio log | Quien lea el log (permisos `0666`) roba la clave | CWE-532 | La clave jamás se registra; solo `api_key=configurada` |

---

## 5. Los cuatro temas en detalle

### 5.1 Apertura y cierre de ficheros

**Problema.** Abrir un fichero parece simple, pero hay tres ataques clásicos: (1) *symlink*: la ruta apunta a otro fichero; (2) *TOCTOU*: se comprueba una cosa y, antes de usarla, cambia; (3) *permisos*: el fichero ya existía con permisos abiertos o es un enlace duro a otro sitio.

**Cómo lo resuelve `al_open`:**

1. Una **única llamada atómica** `open()` con estas banderas:
   - `O_NOFOLLOW`: si la ruta final es un symlink, falla.
   - `O_CREAT` + modo `0600`: si lo crea, solo el dueño accede.
   - `O_APPEND`: cada escritura va al final.
   - `O_CLOEXEC`: el descriptor no se hereda al ejecutar otros programas.
   - `O_NONBLOCK`: una tubería (FIFO) sin lector no deja el programa colgado.
2. **`fstat` sobre el descriptor** (no sobre el nombre): comprueba que es un fichero normal, del mismo usuario, sin permisos de grupo/otros y con un solo nombre (`st_nlink == 1`).
3. Si algo falla, se cierra el descriptor y se devuelve un código de error; el puntero de salida queda en `NULL`.

**Cierre (`al_close`).** Toma `audit_logger **` y deja el puntero del llamador en `NULL`: un segundo cierre o una escritura tardía devuelven `AL_ERR_ARG` en lugar de usar memoria liberada. Hace `fsync` y `close` y comprueba ambos, porque un `close` que falla puede significar datos perdidos. Si `close` falla **no se reintenta** (en Linux el descriptor ya queda liberado).

**Qué NO cubre** (ver sección 8): symlinks en directorios *intermedios* de la ruta, sistemas de ficheros de red, y que `fsync` sea lento.

### 5.2 Certificados

**Qué es un certificado.** Es un "carnet de identidad" digital de un servidor: dice *quién es* (nombre de host), *hasta cuándo vale* y lleva la **firma** de una **CA** (autoridad de certificación) en la que confías. Para fiarte hay que comprobar **las cuatro cosas**:

| Comprobación | Pregunta | Si falla |
|---|---|---|
| Lectura | ¿Es un PEM válido? | `CERT_ERR_PARSE` / `CERT_ERR_IO` |
| Cadena | ¿Lo firmó una CA que yo he elegido? | `CERT_ERR_CHAIN` |
| Fechas | ¿Está dentro de su periodo de validez? | `CERT_ERR_EXPIRED` |
| Host | ¿Es el certificado **de este servidor**? | `CERT_ERR_HOSTNAME` |

**Error típico (R-11).** Comprobar solo que el fichero se lee. Un certificado de otra web, caducado o autofirmado habría dado "certificado OK". Es la causa típica de ataques *man-in-the-middle* (CWE-295).

**Versión segura (`cert_verify_file`).**
- El almacén de confianza (`X509_STORE`) contiene **solo la CA que tú indicas**.
- `X509_VERIFY_PARAM_set1_host` exige que el nombre coincida con el certificado (SAN/CN), sin comodines parciales.
- `X509_STORE_CTX_set_purpose(..., X509_PURPOSE_SSL_SERVER)` exige que sirva para un servidor TLS.
- `X509_verify_cert` comprueba cadena, firmas y fechas con la **hora actual**.
- Patrón `goto done`: un único sitio libera `BIO`, `X509`, `X509_STORE` y `X509_STORE_CTX`, pase lo que pase.

**Cómo se prueba.** `tests/test_cert.c` **fabrica** los certificados con la API de OpenSSL (CA, válido, caducado, aún no válido, autofirmado, de otra CA), así los tests no caducan nunca. Los 14 casos pasan, incluidos: host distinto → `HOSTNAME`; caducado → `EXPIRED`; firmado por otra CA → `CHAIN`; autofirmado fuera del almacén → `CHAIN`; basura → `PARSE`.

**Qué NO cubre:** revocación (CRL/OCSP), *pinning* de clave pública, conexión TLS real (solo valida un fichero PEM), ni la protección de la clave privada. Es la comprobación del certificado, no un cliente TLS completo.

### 5.3 Concurrencia con hilos

**La carrera de datos, con una analogía.** Dos hilos hacen `contador++` sobre una variable global. Esa línea son tres pasos: *leer, sumar, escribir*. Si ambos leen "5" a la vez, los dos escriben "6" y se pierde una cuenta. Con un buffer global compartido es peor: un hilo escribe el texto mientras otro lo reescribe, y salen líneas mezcladas.

**Cómo se comprueba:** ThreadSanitizer (`make test-tsan`) ejecuta 8 hilos × 200 escrituras sobre el mismo logger. Sin carreras de datos. Si se quita el mutex a propósito, TSan avisa de `data race` y falla el test (ver tabla de mutaciones).

**Cómo se arregla en `secure/`:**

1. **Nada global mutable.** Cada hilo recibe su propio `worker_ctx` con su propio campo `result`.
2. **Buffers locales** en `al_write` (viven en la pila del hilo; nadie más los ve).
3. **Un mutex** protege exactamente lo compartido: el contador `seq` y la escritura al fichero. Así el número de línea y el orden en el fichero coinciden.
4. **Un solo mutex** → no puede haber *deadlock* (bloqueo mutuo) por orden de candados.
5. **Quien abre, cierra, y solo después del `join`.** Los hilos no cierran nada.
6. Se **comprueba** `pthread_create`/`pthread_join` y se espera solo a los hilos que de verdad se crearon.

**Contrato importante (no forzado por el código):** no llamar a `al_close` mientras otro hilo está en `al_write`. Está documentado en `logger.h`. Para forzarlo haría falta contar referencias; es un buen ejercicio de ampliación.

### 5.4 Tests

**Qué prueban los 13 tests del logger** (116 comprobaciones):

| Test | Ataque o fallo que cubre |
|---|---|
| Crea fichero con `0600` | R-04 |
| Symlink rechazado | R-02 |
| Permisos abiertos rechazados (`0666` y `0640`) | R-04 |
| Enlace duro rechazado | Ataque con `st_nlink` |
| Directorio / ruta inexistente / FIFO | Aperturas no seguras |
| Argumentos `NULL` o vacíos | CERT API00-C |
| Usuarios inválidos (`"a b"`, `"root\n"`, `"../etc"`, 33 caracteres...) | R-14 |
| Inyección de línea neutralizada (`\n`, `\r`, ESC, tab) | R-14 |
| Mensaje de 5000 bytes recortado con `...` | R-05 |
| Doble cierre y escritura tras cerrar | R-07 |
| Error de escritura notificado (límite de tamaño → `EFBIG`) | R-08 |
| Id de sesión aleatorio (32 hex, dos distintos) | R-10 |
| 8 hilos × 200 escrituras: 1600 líneas, bien formadas, `seq` 1..1600 sin huecos | R-09 |

**Sanitizers (qué son):**
- **AddressSanitizer (ASan):** detecta desbordamientos, uso tras `free`, doble `free` y fugas.
- **UndefinedBehaviorSanitizer (UBSan):** detecta desbordes de enteros con signo, desplazamientos inválidos, etc.
- **ThreadSanitizer (TSan):** detecta carreras de datos. No se puede combinar con ASan, por eso hay dos objetivos (`make test` y `make test-tsan`).

**¿Los tests detectan de verdad los fallos?** Pasar tests no demuestra que los tests sirvan. Se hizo una **prueba de mutación manual**: se rompió el código a propósito y se comprobó que los tests fallan.

| Mutación | Resultado |
|---|---|
| Quitar el mutex de `al_write` | TSan: `data race` y falla el test concurrente |
| Quitar la sanitización de caracteres de control | Falla el test de inyección |
| Quitar `O_NOFOLLOW` | Falla el test de symlink |
| Quitar la comprobación de host del certificado | Falla "host distinto" (devolvía "certificado válido") |

---

## 6. Resultados reales de ejecución

**Compilación de `secure/`** con `-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wshadow`, `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, PIE y `-Wl,-z,relro,-z,now`: **0 avisos**. Que compile sin avisos no demuestra que sea seguro: el compilador no detecta TOCTOU, symlinks, permisos, carreras de datos ni validación de certificados. Para eso están los tests y los sanitizers.

**Prueba de symlink (manual):** se crea `enlace.log` apuntando a `victima.txt` (permisos `0600`) y se ejecuta `AUDIT_LOG=./enlace.log ./bin/secure ana 2 hola`. `al_open` devuelve error, `victima.txt` queda **intacto** y con permisos `0600`.

**Inyección en el log:** un usuario como `"x\n2026-10-23T00:00:00Z seq=1 user=admin msg=acceso concedido"` se rechaza (`AL_ERR_ARG`). Con ese mismo texto como *mensaje*, queda **en una sola línea** con los saltos cambiados por `?`.

**Versión segura bajo sanitizers y valgrind:** con 16 hilos bajo ASan+UBSan y bajo TSan (49 líneas = 1 de sesión + 16×3) y con 4 hilos bajo valgrind: sin errores, sin fugas, sin carreras. Con la clave `AUDIT_API_KEY=secreto123`, buscar `secreto123` en el log da 0 coincidencias.

**Argumentos de hilos inválidos** (`abc`, `-5`, `0`, `99999999999`, `65`): todos rechazados con código de salida 2.

**clang-tidy sobre `secure/`:** quedan avisos que se han revisado y **se aceptan**:
- `clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling` sobre `snprintf`, `memcpy`, `fprintf`: recomienda funciones `*_s` del Anexo K de C11, que **glibc no implementa** y que casi nadie usa. Aquí todos los usos llevan tamaño explícito.
- `cert-err33-c` sobre `fprintf(stderr, ...)` en caminos de error: si falla escribir el propio mensaje de error no hay nada útil que hacer.
- `concurrency-mt-unsafe` sobre `getenv` en `main`: se llama antes de crear hilos y nadie modifica el entorno.

(El único aviso con fundamento real, una conversión `int`→`char` implícita en `sanitize_copy`, se corrigió.)

---

## 7. Regla mental: "cinco preguntas" para cada fichero que abras

1. **¿Abro con una sola llamada atómica** (sin `access()` antes)?
2. **¿Compruebo el resultado** de abrir, escribir y cerrar?
3. **¿Los permisos son mínimos** (`0600`) y verifico que el fichero es el que espero (`fstat`)?
4. **¿Se cierra una sola vez**, en un único sitio, también en los caminos de error?
5. **¿Los datos externos** (argumentos, nombres, mensajes) **se validan** antes de llegar al fichero, a un formato o a un buffer?

---

## 8. Limitaciones y lo que queda por hacer

Para no dar una falsa sensación de seguridad, esto **no** está resuelto:

- **Symlinks en directorios intermedios.** `O_NOFOLLOW` solo mira el último componente de la ruta. Si `/ruta/dir/` es un symlink manipulable, no se detecta. Solución más completa: `openat` con `O_NOFOLLOW` componente a componente, o `openat2` con `RESOLVE_NO_SYMLINKS` (Linux 5.6+).
- **`O_APPEND` en sistemas de ficheros de red (NFS)** no garantiza escrituras atómicas entre procesos distintos. Dentro de un solo proceso las serializa el mutex.
- **Cierre concurrente:** el contrato "no cerrar mientras otro hilo escribe" depende de quien use la librería.
- **Recorte de mensajes** por bytes: puede cortar en mitad de un carácter UTF-8 multibyte.
- **Integridad del log:** un atacante con permisos del mismo usuario puede borrar o editar el fichero. Para auditoría real se necesitaría un log remoto, cadena de hashes o fichero *append-only* (`chattr +a`).
- **Test de "disco lleno" simulado** con `RLIMIT_FSIZE`, no con un disco lleno real; no se prueba fallo de `fsync`.
- **Certificados:** sin revocación, sin *pinning*, sin conexión TLS real.
- **Sin cobertura de código ni *fuzzing*.** Siguiente paso razonable: `gcov` para medir cobertura y `libFuzzer` sobre `al_write`.
- **Entorno:** probado en Linux (glibc, GCC 13, OpenSSL 3.0). Usa APIs POSIX (`open`, `fstat`, `getrandom`...), así que no compila tal cual en Windows.

---

## 9. Glosario rápido

| Término | Significado |
|---|---|
| **Buffer** | Zona de memoria con tamaño fijo, por ejemplo un array de `char` |
| **Desbordamiento** | Escribir más allá del final de un buffer |
| **Descriptor (`fd`)** | Número que el sistema da a un fichero abierto |
| **TOCTOU** | *Time Of Check To Time Of Use*: lo que comprobaste cambia antes de usarlo |
| **Symlink** | Enlace simbólico: un nombre que apunta a otro fichero |
| **Carrera de datos** | Dos hilos acceden a la misma memoria a la vez y uno escribe |
| **Mutex** | Candado: solo un hilo a la vez en la zona protegida |
| **Deadlock** | Dos hilos esperan el uno al otro para siempre |
| **Sanitizer** | Herramienta del compilador que vigila errores en tiempo de ejecución |
| **UB** | Comportamiento indefinido: el estándar no garantiza nada |
| **CA** | Autoridad de certificación: firma los certificados |
| **SAN** | *Subject Alternative Name*: lista de nombres de host válidos del certificado |
| **CERT C** | Guía de programación segura en C del SEI (Carnegie Mellon) |
| **CWE** | Catálogo público de tipos de debilidades de software |

---

## 10. Lectura recomendada

- SEI CERT C Coding Standard (busca cada regla por su código: `FIO45-C`, `STR31-C`, `CON43-C`...).
- CWE Top 25 (cwe.mitre.org).
- Páginas del manual: `man 2 open`, `man 2 fstat`, `man 3 pthread_mutex_lock`, `man 2 getrandom`.
- Documentación de OpenSSL: `X509_verify_cert(3)` y `X509_VERIFY_PARAM_set1_host(3)`.
