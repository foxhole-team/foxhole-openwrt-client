export function upstreams() {
	return [
		{ type: 'udp', address: '192.0.2.53:53' },
		{ type: 'tcp', address: '[2001:db8::53]:5353' },
		{ type: 'dot', host: 'dns.example', port: 1853,
			server_ip: '192.0.2.53', insecure: false },
		{ type: 'doh', url: 'https://dns.example:18443/dns-query',
			server_ip: '2001:db8::53', insecure: false }
	];
};

export function profile(upstream) {
	return {
		schema_version: 1,
		outbound: { type: 'vless', server: 'group.example', port: 8443,
			uuid: 'd0cf0001-0000-4000-8000-000000000000',
			tls: { enabled: true, server_name: 'tls.example', insecure: false } },
		tun: { mtu: 1400, ipv4: '10.0.0.1' },
		bootstrap_dns: { domains: ['GROUP.example.'],
			upstreams: [upstream], timeout_ms: 3000, max_candidates: 8 }
	};
};
