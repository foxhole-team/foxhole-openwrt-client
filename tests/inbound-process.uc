let failures = 0, passed = 0, raw = null;
let fs = { readfile: () => raw };

// The revoke-helper process snapshot is injected below.

function check(name, test) {
	try { test(); passed++; print('ok ' + name); }
	catch (error) { failures++; warn('not ok ' + name + ': ' + error); }
};
function expect(value) { if (!value) die('assertion_failed'); };
function record(comm, state, start) {
	let fields = [ state ];
	for (let index = 1; index < 50; index++) push(fields, '' + (100 + index));
	fields[19] = start;
	return '123 (' + comm + ') ' + join(' ', fields);
};

check('starttime is Linux field 22 after the entire process comm', () => {
	raw = record('hysteria', 'S', '7654321');
	let result = snapshot(123);
	expect(result.start == '7654321' && result.zombie == false);
});
check('spaces and parentheses in process comm do not shift starttime', () => {
	raw = record('odd (name) here', 'S', '7654322');
	expect(snapshot(123).start == '7654322');
});
check('zombie state is recognized independently of process comm', () => {
	raw = record('hysteria', 'Z', '7654323');
	expect(snapshot(123).zombie == true);
});
check('a disappeared process yields no owner snapshot', () => {
	raw = null;
	expect(snapshot(123) == null);
});
for (let value in [ '123 hysteria S 1 2', record('hysteria', 'S', 'invalid') ]) {
	check('malformed process identity cannot establish ownership', () => {
		raw = value;
		let rejected = false;
		try { snapshot(123); } catch (_) { rejected = true; }
		expect(rejected);
	});
}
print('Incoming process identity tests: ' + passed + ' passed, ' + failures + ' failed');
exit(failures ? 1 : 0);
