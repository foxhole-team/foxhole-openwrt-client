'use strict';
import * as fs from 'fs';

const api = 'https://api.github.com/repos/foxhole-team/foxhole-openwrt-client';
const web = 'https://github.com/foxhole-team/foxhole-openwrt-client';
const tag = ARGV[0], filename = ARGV[1], stable = ARGV[2];
if (!match(tag, /^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/) ||
    type(filename) != 'string' || length(filename) > 128 ||
    stable != web + '/releases/download/' + tag + '/' + filename) exit(1);

let raw = '', part;
while ((part = fs.stdin.read(8192)) != null && length(part)) {
 if (length(raw) + length(part) > 262144) exit(1);
 raw += part;
}
let release = json(raw);
function id(value) { return type(value) == 'int' && value > 0 && value <= 9007199254740991; }
if (type(release) != 'object' || release.tag_name != tag || type(release.draft) != 'bool' || release.draft != false ||
    !id(release.id) || release.url != api + '/releases/' + release.id ||
    release.html_url != web + '/releases/tag/' + tag ||
    type(release.assets) != 'array' || length(release.assets) > 1024) exit(1);
let selected = null;
for (let asset in release.assets) {
 if (asset?.name != filename) continue;
 if (selected != null || !id(asset.id) || type(asset.size) != 'int' ||
     asset.size <= 0 || asset.size > 268435456 || asset.state != 'uploaded' ||
     asset.browser_download_url != stable || asset.url != api + '/releases/assets/' + asset.id ||
     type(asset.digest) != 'string' || !match(asset.digest, /^sha256:[a-f0-9]{64}$/)) exit(1);
 selected = asset.id;
}
if (selected == null) exit(1);
print(selected);
