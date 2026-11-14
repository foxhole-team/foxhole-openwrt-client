'use strict';
import * as fs from 'fs';
import * as native from '/usr/share/foxhole/update-native.uc';

// The driver provides synthetic /etc files
// in an isolated container tmpfs.
if (getenv('FOXHOLE_ISOLATED_POLICY_FIXTURE') != '1') die('Isolated fixture required\n');
let observed = ARGV[0], policy = json(fs.readfile('/source/package/foxhole-openwrt-client/root/usr/share/foxhole/update-policy.json'));
let path = '/tmp/qualified-policy.json';
function save(value) {
 let raw = sprintf('%J', value);
 if (fs.writefile(path, raw) != length(raw) || !fs.chmod(path, 0o600)) die('Fixture write failed\n');
};
save(policy);
let accepted = false;
try {
 let checked = native.policy(path, policy.packageVersion);
 accepted = checked.packageVersion == policy.packageVersion;
} catch (error) {
 if (observed != '25.12.7') die('Native policy rejected qualified firmware: ' + error + '\n');
}
if (accepted != (observed == '25.12.5' || observed == '25.12.6')) die('Wrong firmware admission\n');
if (accepted) {
 let changed = { ...policy, supportedOpenWrt: ['25.12.5', '25.12.7'] };
 save(changed);
 let refused = false;
 try { native.policy(path, policy.packageVersion); } catch (_) { refused = true; }
 if (!refused) die('Unqualified list accepted\n');
}
printf('PASS cold native.policy import and firmware admission %s\n', observed);
