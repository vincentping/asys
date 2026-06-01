CC      := gcc
CFLAGS  := -O2 -Wall -pthread
CORE    := src/asyd/core
HANDLERS:= src/asyd/handlers
CONF    := tests/conformance
VERSION := 0.3.1
DIST_TAR := asyd-$(VERSION).tar.gz

# ── Main daemon ──────────────────────────────────────────────
bin/asyd: src/asyd/asyd.c \
      $(CORE)/apdu_parser.c \
      $(CORE)/dispatcher.c \
      $(CORE)/monocypher.c \
      $(CORE)/crypto_utils.c \
      $(CORE)/noise_ik.c \
      $(CORE)/whitelist.c \
      $(CORE)/auth_verify.c \
      $(CORE)/task_pool.c \
      $(HANDLERS)/sys_caps.c \
      $(HANDLERS)/sys_hello.c \
      $(HANDLERS)/sys_status.c \
      $(HANDLERS)/sys_procs.c \
      $(HANDLERS)/proc_throttle.c \
      $(HANDLERS)/svc_restart.c \
      $(HANDLERS)/task_query.c
	@mkdir -p bin
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

asyd: bin/asyd

# ── Conformance tests ────────────────────────────────────────
$(CONF)/test_noise_ik: $(CONF)/test_noise_ik.c $(CORE)/noise_ik.c $(CORE)/crypto_utils.c $(CORE)/monocypher.c
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

$(CONF)/test_whitelist: $(CONF)/test_whitelist.c $(CORE)/whitelist.c $(CORE)/monocypher.c
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

$(CONF)/test_apdu_parser: $(CONF)/test_apdu_parser.c $(CORE)/apdu_parser.c $(CORE)/monocypher.c $(CORE)/noise_ik.c $(CORE)/crypto_utils.c
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

PHASE2_SRCS := $(CORE)/apdu_parser.c \
               $(CORE)/dispatcher.c \
               $(CORE)/task_pool.c \
               $(CORE)/monocypher.c \
               $(CORE)/crypto_utils.c \
               $(CORE)/noise_ik.c \
               $(CORE)/whitelist.c \
               $(CORE)/auth_verify.c \
               $(HANDLERS)/sys_caps.c \
               $(HANDLERS)/sys_hello.c \
               $(HANDLERS)/sys_status.c \
               $(HANDLERS)/sys_procs.c \
               $(HANDLERS)/proc_throttle.c \
               $(HANDLERS)/svc_restart.c \
               $(HANDLERS)/task_query.c

$(CONF)/test_handlers: $(CONF)/test_handlers.c $(PHASE2_SRCS)
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

$(CONF)/test_task_pool: $(CONF)/test_task_pool.c $(CORE)/task_pool.c
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

$(CONF)/test_proc_throttle: $(CONF)/test_proc_throttle.c $(PHASE2_SRCS)
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

$(CONF)/test_svc_restart: $(CONF)/test_svc_restart.c $(PHASE2_SRCS)
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@ -ldl

$(CONF)/test_task_query: $(CONF)/test_task_query.c $(PHASE2_SRCS)
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

AUTH_SRCS := $(CORE)/crypto_utils.c \
             $(CORE)/auth_verify.c \
             $(CORE)/apdu_parser.c \
             $(CORE)/monocypher.c

$(CONF)/test_auth_verify: $(CONF)/test_auth_verify.c $(AUTH_SRCS)
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

SEQ_SRCS := $(CORE)/crypto_utils.c \
            $(CORE)/monocypher.c

$(CONF)/test_seq_replay: $(CONF)/test_seq_replay.c $(SEQ_SRCS)
	$(CC) $(CFLAGS) $^ -I$(CORE) -o $@

$(CONF)/test_client_magic: $(CONF)/test_client_magic.c
	$(CC) $(CFLAGS) $^ -o $@

TESTS := $(CONF)/test_noise_ik $(CONF)/test_whitelist \
         $(CONF)/test_apdu_parser $(CONF)/test_handlers \
         $(CONF)/test_task_pool $(CONF)/test_proc_throttle \
         $(CONF)/test_svc_restart $(CONF)/test_task_query \
         $(CONF)/test_auth_verify $(CONF)/test_seq_replay \
         $(CONF)/test_client_magic

tests: $(TESTS)

# ── Run all conformance tests ────────────────────────────────
check: tests
	@echo "=== test_noise_ik ===" && $(CONF)/test_noise_ik
	@echo "=== test_whitelist ===" && $(CONF)/test_whitelist
	@echo "=== test_apdu_parser ===" && $(CONF)/test_apdu_parser
	@echo "=== test_handlers ===" && $(CONF)/test_handlers
	@echo "=== test_task_pool ===" && $(CONF)/test_task_pool
	@echo "=== test_proc_throttle ===" && $(CONF)/test_proc_throttle
	@echo "=== test_svc_restart ===" && $(CONF)/test_svc_restart
	@echo "=== test_task_query ===" && $(CONF)/test_task_query
	@echo "=== test_auth_verify ===" && $(CONF)/test_auth_verify
	@echo "=== test_seq_replay ===" && $(CONF)/test_seq_replay
	@echo "=== test_client_magic ===" && $(CONF)/test_client_magic

# ── Packaging ────────────────────────────────────────────────
$(DIST_TAR):
	git archive --format=tar.gz --prefix=asyd-$(VERSION)/ HEAD > $(DIST_TAR)

dist: $(DIST_TAR)

rpm: $(DIST_TAR)
	mkdir -p ~/rpmbuild/SOURCES ~/rpmbuild/SPECS
	cp $(DIST_TAR) ~/rpmbuild/SOURCES/
	cp deploy/asyd.spec ~/rpmbuild/SPECS/
	rpmbuild -bb ~/rpmbuild/SPECS/asyd.spec
	cp ~/rpmbuild/RPMS/x86_64/asyd-$(VERSION)-1.*.rpm .

deb: $(DIST_TAR)
	rm -rf /tmp/asyd-deb
	mkdir -p /tmp/asyd-deb
	tar xf $(DIST_TAR) -C /tmp/asyd-deb
	cp -r deploy/debian /tmp/asyd-deb/asyd-$(VERSION)/
	cd /tmp/asyd-deb/asyd-$(VERSION) && dpkg-buildpackage -us -uc -b
	cp /tmp/asyd-deb/asyd_$(VERSION)-1_*.deb .

# ── Shortcuts ────────────────────────────────────────────────
all: bin/asyd tests

clean:
	rm -f bin/asyd $(TESTS) $(CONF)/test_tofu $(DIST_TAR)

.PHONY: all tests check clean dist rpm deb
