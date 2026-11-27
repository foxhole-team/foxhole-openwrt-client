#ifndef FOXHOLE_RAM_HTTPS_POLICY_H
#define FOXHOLE_RAM_HTTPS_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#define FOXHOLE_GITHUB_ORIGIN "https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/"
#define FOXHOLE_RELEASE_CDN "https://release-assets.githubusercontent.com/github-production-release-asset/1361759440/"

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

static inline bool foxhole_number(const char **cursor, bool positive)
{
	const char *first = *cursor, *p = first;
	while (*p >= '0' && *p <= '9') p++;
	if (p == first || p - first > 6 || (*first == '0' && (positive || p - first != 1))) return false;
	*cursor = p;
	return true;
}

static inline const char *foxhole_github_filename(const char *url)
{
	const char *p, *version, *filename;
	size_t length;
	bool bank;
	if (!foxhole_https_url(url) || strncmp(url, FOXHOLE_GITHUB_ORIGIN, sizeof(FOXHOLE_GITHUB_ORIGIN)-1)) return NULL;
	p = url + sizeof(FOXHOLE_GITHUB_ORIGIN)-1;
	if (*p++ != 'v') return NULL;
	version = p;
	for (int i = 0; i < 3; i++) {
		if (!foxhole_number(&p, false) || (i < 2 && *p++ != '.')) return NULL;
	}
	length = p - version;
	if (*p++ != '/') return NULL;
	filename = p;
	static const char base_prefix[] = "foxhole-openwrt-client-", bank_prefix[] = "foxhole-ram-bootstrap-bank-";
	if (!strncmp(p, base_prefix, sizeof(base_prefix)-1)) { bank = false; p += sizeof(base_prefix)-1; }
	else if (!strncmp(p, bank_prefix, sizeof(bank_prefix)-1)) { bank = true; p += sizeof(bank_prefix)-1; }
	else return NULL;
	if (strncmp(p, version, length)) return NULL;
	p += length;
	if (strncmp(p, "-r", 2)) return NULL;
	p += 2;
	if (!foxhole_number(&p, true)) return NULL;
	if (bank) {
		if (strcmp(p, "-aarch64_cortex-a53.apk") && strcmp(p, "-x86_64.apk")) return NULL;
	} else if (strcmp(p, ".apk")) return NULL;
	return filename;
}

static inline bool foxhole_reserved_host(const char *url)
{
	const char *p = url+8, *end = p + strcspn(p, "/:");
	static const char *const hosts[] = { "github.com", "api.github.com", "release-assets.githubusercontent.com",
		"objects.githubusercontent.com", "github-releases.githubusercontent.com" };
	while (end > p && end[-1] == '.') end--;
	for (size_t i = 0; i < sizeof(hosts)/sizeof(hosts[0]); i++)
		if (strlen(hosts[i]) == (size_t)(end-p) && !strncasecmp(p, hosts[i], end-p)) return true;
	return false;
}

static inline bool foxhole_disposition(const char *p, const char *end, const char *filename)
{
	static const char prefix[] = "attachment; filename=";
	char decoded[160];
	size_t used = 0;
	while (p < end && used < sizeof(decoded)-1) {
		unsigned char ch = (unsigned char)*p++;
		if (ch == '%') {
			if (end-p < 2) return false;
			int hi = foxhole_hex((unsigned char)p[0]), lo = foxhole_hex((unsigned char)p[1]);
			if (hi < 0 || lo < 0) return false;
			ch = (unsigned char)(hi*16+lo); p += 2;
		} else if (ch == '+') ch = ' ';
		if (ch < 32 || ch >= 127) return false;
		decoded[used++] = (char)ch;
	}
	if (p != end) return false;
	decoded[used] = 0;
	return !strncmp(decoded,prefix,sizeof(prefix)-1) && !strcmp(decoded+sizeof(prefix)-1,filename);
}

static inline bool foxhole_github_hop(const char *origin, const char *url)
{
	const char *filename = foxhole_github_filename(origin), *p;
	unsigned signatures = 0, disposition = 0;
	if (!filename || strncmp(url,FOXHOLE_RELEASE_CDN,sizeof(FOXHOLE_RELEASE_CDN)-1)) return false;
	p = url+sizeof(FOXHOLE_RELEASE_CDN)-1;
	for (int i=0; i<36; i++) {
		if (!*p) return false;
		int value = foxhole_hex((unsigned char)*p);
		if (i==8 || i==13 || i==18 || i==23) { if (*p!='-') return false; }
		else if (value<0) return false;
		p++;
	}
	if (*p++ != '?') return false;
	while (*p) {
		const char *end = p+strcspn(p,"&"), *eq=memchr(p,'=',end-p);
		unsigned bit=0;
		if (!eq || eq==p || eq+1==end) return false;
		for (const char *k=p; k<eq; k++)
			if (!((*k>='a' && *k<='z') || (*k>='0' && *k<='9') || *k=='-')) return false;
		for (const char *v=eq+1; v<end; v++) {
			if (*v==';' || *v=='?' || *v=='"') return false;
			if (*v=='%') {
				if (end-v<3 || foxhole_hex((unsigned char)v[1])<0 || foxhole_hex((unsigned char)v[2])<0) return false;
				v+=2;
			}
		}
		size_t len=eq-p;
		if (len==4 && !memcmp(p,"rscd",4)) bit=1;
		if (len==28 && !memcmp(p,"response-content-disposition",28)) bit=2;
		if (bit) {
			if ((disposition&bit) || !foxhole_disposition(eq+1,end,filename)) return false;
			disposition |= bit;
		}
		if (len==3 && (!memcmp(p,"sig",3) || !memcmp(p,"jwt",3))) {
			unsigned kind = !memcmp(p,"sig",3) ? 1U : 2U;
			if (signatures & kind) return false;
			signatures |= kind;
		}
		if (*end && !end[1]) return false;
		p=*end ? end+1 : end;
	}
	return disposition && signatures;
}

static inline bool foxhole_recovery_hop(bool github, const char *origin, const char *url, unsigned count)
{
	if (!foxhole_https_url(origin) || !foxhole_https_url(url)) return false;
	if (github) return count==0 && foxhole_github_hop(origin,url);
	if (count>=3 || foxhole_reserved_host(origin) || foxhole_reserved_host(url)) return false;
	size_t n=strcspn(origin+8,"/");
	return n==strcspn(url+8,"/") && !strncasecmp(origin+8,url+8,n);
}

static inline bool foxhole_recovery_arguments(int argc, char **argv)
{
	bool github=argc>1 && !strcmp(argv[1],"--github-release");
	if (github) {
		if (argc!=3) return false;
		argc--; argv++;
	}
	if (argc==4) {
		if (strcmp(argv[1],"--ca-certificate") || argv[2][0]!='/' || !argv[2][1]) return false;
		for (const unsigned char *at=(const unsigned char *)argv[2]; *at; at++)
			if (*at<=32 || *at>=127 || *at=='\\') return false;
	} else if (argc!=2) return false;
	const char *url=argv[argc-1];
	if (!foxhole_https_url(url)) return false;
	return github ? foxhole_github_filename(url)!=NULL : !foxhole_reserved_host(url);
}

#endif
