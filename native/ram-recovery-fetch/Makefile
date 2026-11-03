# Use matching unstripped link inputs; installed runtime libraries stay unchanged.
.PHONY: all
all:
	test -n "$(OUT)" -a -n "$(RECOVERY_HEADERS)" -a -n "$(RECOVERY_LINK_LIBS)"
	test -n "$(RECOVERY_SDK_INCLUDE)" -a -n "$(RECOVERY_FORTIFY_HEADERS)"
	test "$(RECOVERY_PAGE_SIZE)" = 4096
	$(CC) -Os -pipe $(RECOVERY_ARCH_CFLAGS) -std=gnu99 -Wall -Wextra \
		-Wformat -Werror=format-security -Wno-unused-parameter \
		-fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=1 \
		-I"$(RECOVERY_FORTIFY_HEADERS)" -I"$(RECOVERY_HEADERS)" -I. uclient-fetch.c progress.c \
		"$(RECOVERY_LINK_LIBS)/libuclient.so" "$(RECOVERY_LINK_LIBS)/libubox.so.20260213" \
		-specs="$(RECOVERY_SDK_INCLUDE)/hardened-ld-pie.specs" \
		-Wl,-rpath-link,"$(RECOVERY_LINK_LIBS)" \
		-Wl,-z,relro,-z,now,-z,noexecstack,-z,pack-relative-relocs \
		-Wl,-z,max-page-size=4096,-z,common-page-size=4096 -o "$(OUT)"
	$(STRIP) --strip-unneeded "$(OUT)"
