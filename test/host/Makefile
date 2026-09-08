# Basanos — host tests. No ESP-IDF, no hardware, no network.
#
#   make            build and run
#   make asan       the same under AddressSanitizer + UBSan
#   make clean
#
# The engines must build with a plain compiler. If this Makefile ever needs an
# ESP-IDF include path, something has leaked into the pure layer.

CC      ?= cc
ROOT    := ../..
ENGINE  := $(ROOT)/components/engine
RBAC    := $(ROOT)/components/rbac
SCORE   := $(ROOT)/components/score

CFLAGS  := -std=c11 -O1 -g \
           -Wall -Wextra -Werror \
           -Wno-unused-parameter \
           -I$(ENGINE)/include -I$(RBAC)/include -I$(SCORE)/include

SRC := $(ENGINE)/basanos.c \
       $(ENGINE)/target.c \
       $(ENGINE)/engage.c \
       $(ENGINE)/family.c \
       $(ENGINE)/station.c \
       $(ENGINE)/ie.c \
       $(ENGINE)/wpspin.c \
       $(ENGINE)/pixie.c \
       $(ENGINE)/survey.c \
       $(RBAC)/sha256.c \
       $(RBAC)/rbac.c \
       $(RBAC)/sha1.c \
       $(RBAC)/wpa.c \
       $(SCORE)/score.c \
       $(SCORE)/alarm.c

TESTS := main.c \
         test_target.c \
         test_engage.c \
         test_family.c \
         test_rbac.c \
         test_wpa.c \
         test_score.c \
         test_station.c \
         test_ie.c \
         test_wps.c \
         test_wpspin.c \
         test_pixie.c \
         test_survey.c \
         test_alarm.c

BIN := basanos_tests

.PHONY: all run asan clean
all: run

$(BIN): $(SRC) $(TESTS)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(TESTS)

run: $(BIN)
	./$(BIN)

asan: $(SRC) $(TESTS)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer \
	      -o $(BIN)_asan $(SRC) $(TESTS)
	./$(BIN)_asan

clean:
	rm -rf $(BIN) $(BIN)_asan *.dSYM
