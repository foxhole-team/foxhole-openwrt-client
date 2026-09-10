const url = new URL('http://127.0.0.1:8088/cgi-bin/luci/admin/services/foxhole');

try {
  const response = await fetch(url, {
    redirect: 'manual', signal: AbortSignal.timeout(5000)
  });
  if (response.status >= 500) throw new Error();
  console.log(`FoxHole in local OpenWrt: ${url}`);
  console.log('Sign in to LuCI, then unlock FoxHole with the panel PIN.');
  console.log('This command uses no mock API or synthetic measurements.');
} catch {
  console.error('Local OpenWrt is unavailable on 127.0.0.1:8088.');
  console.error('Start the existing development container and retry.');
  process.exitCode = 1;
}
