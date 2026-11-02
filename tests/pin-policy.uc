'use strict';
import * as pin from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/pin-policy.uc';
const BOOT = '00000000-0000-0000-0000-000000000001';
const NEXT_BOOT = '00000000-0000-0000-0000-000000000002';
let passed = 0, failed_count = 0;
function equal(actual, expected) { if (sprintf('%J', actual) != sprintf('%J', expected)) die('assertion'); };
function rejects(fn) { let caught = false; try { fn(); } catch (_) { caught = true; } equal(caught, true); };
function test(name, fn) {
 try { fn(); passed++; print('ok - ', name, '\n'); }
 catch (error) { failed_count++; print('not ok - ', name, ': ', error, '\n'); }
};
function six(value, now) { for (let i = 0; i < 6; i++) value = pin.failed(value, now, BOOT); return value; };
test('initial state has no PIN delay', () => { let v = pin.initial(1000, BOOT); equal(v.failures, 0); equal(pin.remaining(v, 1000), 0); });
test('first five failures do not block', () => { let v = null; for (let i = 0; i < 5; i++) v = pin.failed(v, 1000, BOOT); equal(v.failures, 5); equal(pin.remaining(v, 1000), 0); });
test('sixth failure blocks for sixty seconds', () => { let v = six(null, 1000); equal(v.tier, 1); equal(v.failures, 0); equal(pin.remaining(v, 1000), 60); });
test('remaining seconds round upwards and expire exactly', () => { let v = six(null, 1000); equal(pin.remaining(v, 1001), 60); equal(pin.remaining(v, 60999), 1); equal(pin.remaining(v, 61000), 0); });
test('blocked attempts do not advance failure tier', () => { let v = six(null, 1000); let next = pin.failed(v, 2000, BOOT); equal(next.tier, 1); equal(next.failures, 0); equal(next.blockedUntilUptimeMs, 61000); });
test('second group blocks for five minutes', () => { let v = six(six(null, 1000), 61000); equal(v.tier, 2); equal(pin.remaining(v, 61000), 300); });
test('further groups keep the five-minute cap', () => { let v = six(six(six(null, 1000), 61000), 361000); equal(v.tier, 2); equal(pin.remaining(v, 361000), 300); });
test('rpcd restart preserves the serialized tier and deadline', () => { let v = six(null, 1000); v = pin.checked(json(sprintf('%J', v)), 2000, BOOT); equal(pin.remaining(v, 2000), 59); });
test('success reset makes next group sixty seconds again', () => { let v = six(six(null, 1000), 61000); v = pin.initial(400000, BOOT); v = six(v, 400000); equal(v.tier, 1); equal(pin.remaining(v, 400000), 60); });
test('a different boot resets stale monotonic state', () => { let v = six(null, 1000); v = pin.checked(v, 0, NEXT_BOOT); equal(v.tier, 0); equal(v.bootId, NEXT_BOOT); });
test('same-boot clock regression fails closed', () => { rejects(() => pin.checked(six(null, 1000), 999, BOOT)); });
test('malformed records and foreign fields fail closed', () => { rejects(() => pin.checked({ ...pin.initial(1, BOOT), failures: 6 }, 2, BOOT)); rejects(() => pin.checked({ ...pin.initial(1, BOOT), extra: true }, 2, BOOT)); rejects(() => pin.checked({ ...pin.initial(1, BOOT), tier: 3 }, 2, BOOT)); });
test('oversized and invalid clocks fail closed', () => { rejects(() => pin.initial(-1, BOOT)); rejects(() => pin.initial(1.5, BOOT)); rejects(() => pin.initial(9007199254740991, BOOT)); rejects(() => pin.initial(1, 'invalid')); });
print('# PIN policy: ', passed, ' passed, ', failed_count, ' failed\n');
exit(failed_count ? 1 : 0);
