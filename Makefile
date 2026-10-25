# Makefile  --  ejemplo de seguridad en C (ver DOCUMENTACION.md)
#
#   make            compila bin/secure
#   make test       tests con AddressSanitizer + UBSan (memoria y comportamiento indefinido)
#   make test-tsan  test de concurrencia con ThreadSanitizer (carreras de datos)
#   make check      test + test-tsan
#   make clean
#
# Se usa C11. (Con GCC 14+ tambien vale -std=c23; con GCC 13 seria -std=c2x.)

CC      ?= gcc
STD     := -std=c11
DEFS    := -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
WARN    := -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wshadow
LIBS    := -lpthread -lcrypto

# Endurecimiento del binario "de produccion".
HARDEN  := -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
HARDLD  := -pie -Wl,-z,relro,-z,now

SEC_SRC := secure/main.c secure/logger.c secure/cert_check.c

SAN_ASAN := -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
SAN_TSAN := -fsanitize=thread -g -O1

.PHONY: all test test-tsan check clean
all: bin/secure

bin:
	mkdir -p bin

bin/secure: $(SEC_SRC) secure/*.h | bin
	$(CC) $(STD) $(DEFS) $(WARN) $(HARDEN) $(SEC_SRC) -o $@ $(HARDLD) $(LIBS)

bin/test_logger_asan: tests/test_logger.c secure/logger.c secure/logger.h | bin
	$(CC) $(STD) $(DEFS) $(WARN) $(SAN_ASAN) tests/test_logger.c secure/logger.c -o $@ -lpthread

bin/test_logger_tsan: tests/test_logger.c secure/logger.c secure/logger.h | bin
	$(CC) $(STD) $(DEFS) $(WARN) $(SAN_TSAN) tests/test_logger.c secure/logger.c -o $@ -lpthread

bin/test_cert_asan: tests/test_cert.c secure/cert_check.c secure/cert_check.h | bin
	$(CC) $(STD) $(DEFS) $(WARN) $(SAN_ASAN) tests/test_cert.c secure/cert_check.c -o $@ $(LIBS)

test: bin/test_logger_asan bin/test_cert_asan
	./bin/test_logger_asan
	./bin/test_cert_asan

test-tsan: bin/test_logger_tsan
	./bin/test_logger_tsan

check: test test-tsan

clean:
	rm -rf bin
