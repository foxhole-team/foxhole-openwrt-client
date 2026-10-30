import * as store from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/private-store.uc';
import * as fs from 'fs';

let passed = 0, failed = 0;
function equal(actual, expected) {
	if (actual != expected) die('assertion');
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (_) { failed++; print('not ok ', name, '\n'); }
};
test('private directories require a root-owned real directory', () => {
	let good = { type: 'directory', uid: 0, mode: 0o700, inode: 1 };
	equal(store.directory_metadata(good), true);
	for (let item in [ { ...good, uid: 1000 }, { ...good, mode: 0o755 },
		{ ...good, type: 'link' }, { ...good, type: 'file' } ])
		equal(store.directory_metadata(item), false);
});
test('fixed secret files cannot be foreign, shared or symlinked', () => {
	let good = { type: 'file', uid: 0, mode: 0o600, inode: 1, nlink: 1 };
	equal(store.file_metadata(good), true);
	for (let item in [ { ...good, uid: 1000 }, { ...good, mode: 0o644 },
		{ ...good, nlink: 2 }, { ...good, type: 'link' } ])
		equal(store.file_metadata(item), false);
});
test('lstat refuses a real dangling link before a file can be opened', () => {
	let directory = fs.mkdtemp('/tmp/foxhole-private-store.XXXXXX');
	if (!directory) die('temporary_failed');
	let path = directory + '/link';
	if (!fs.symlink('/missing-synthetic-target', path)) die('link_failed');
	let info = fs.lstat(path);
	equal(info.type, 'link');
	equal(store.file_metadata(info), false);
	fs.unlink(path); fs.rmdir(directory);
});
print('# private store tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
