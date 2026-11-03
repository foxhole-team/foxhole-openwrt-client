#ifndef FOXHOLE_RAM_HTTPS_POLICY_H
#define FOXHOLE_RAM_HTTPS_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static inline int foxhole_hex(unsigned char value)
{
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}

static inline bool foxhole_https_url(const char *url)
{
	const char *authority, *end, *port;
	unsigned int number = 0;
	size_t bytes;
	if (!url || (bytes = strlen(url)) < 10 || bytes > 8192 || strncmp(url, "https://", 8)) return false;
	for (size_t i = 0; i < bytes; i++) {
		unsigned char ch = (unsigned char)url[i];
		if (ch <= 32 || ch >= 127 || ch == '\\' || ch == '#') return false;
		if (ch == '%' && i + 2 < bytes) {
			int high = foxhole_hex(url[i+1]), low = foxhole_hex(url[i+2]);
			if (high >= 0 && low >= 0) {
				int decoded = 16 * high + low;
				if (decoded <= 31 || decoded == 127 || decoded == '\\') return false;
			}
		}
	}
	authority = url + 8;
	end = strchr(authority, '/');
	if (!end || end == authority) return false;
	port = NULL;
	for (const char *at = authority; at < end; at++) {
		unsigned char ch = (unsigned char)*at;
		if (ch == ':') { if (port || at == authority) return false; port = at + 1; continue; }
		if (port) { if (ch < '0' || ch > '9' || at - port >= 5) return false; number = number * 10 + ch - '0'; }
		else if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-')) return false;
	}
	return !port || (port < end && number > 0 && number <= 65535);
}

static inline bool foxhole_recovery_arguments(int argc, char **argv)
{
	if (argc == 2) return foxhole_https_url(argv[1]);
	if (argc != 4 || strcmp(argv[1], "--ca-certificate") || argv[2][0] != '/' || !argv[2][1]) return false;
	for (const unsigned char *at = (const unsigned char *)argv[2]; *at; at++)
		if (*at <= 32 || *at >= 127 || *at == '\\') return false;
	return foxhole_https_url(argv[3]);
}

#endif
