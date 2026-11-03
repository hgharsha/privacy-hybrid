// Screenshots of the UI in light/dark at desktop and phone width. Usage: BASE=... OUT=dir PW=... node scripts/screenshots.mjs
const { chromium } = await import(process.env.PW || 'playwright-core');
const B = process.env.BASE || 'http://127.0.0.1:8799', OUT = process.env.OUT || '.';
const b = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
const sizes = { desktop: { width: 1280, height: 800 }, phone: { width: 390, height: 800 }, small: { width: 320, height: 640 } };
for (const [sn, vp] of Object.entries(sizes)) for (const scheme of ['light', 'dark']) {
  const ctx = await b.newContext({ viewport: vp, colorScheme: scheme }); const p = await ctx.newPage();
  await new Promise((r) => setTimeout(r, 13000)); // registration rate limit: 5 a minute
  await p.goto(B); await p.waitForSelector('#login:not([hidden])'); await p.screenshot({ path: `${OUT}/${sn}-${scheme}-login.png` });
  await p.click('#switchMode'); await p.fill('#email', `s-${sn}-${scheme}@example.com`); await p.fill('#pw', 'screenshot-pass-1'); await p.click('#loginBtn');
  await p.waitForSelector('#app:not([hidden])');
  await p.setInputFiles('#file', new URL('../samples/maria_statement.txt', import.meta.url).pathname); await p.waitForSelector('#docs li', { state: 'attached' });
  await p.screenshot({ path: `${OUT}/${sn}-${scheme}-app.png` });
  if (vp.width < 760) { await p.click('#sideBtn'); await p.screenshot({ path: `${OUT}/${sn}-${scheme}-menu.png` }); }
  await p.click('#setBtn'); await p.waitForTimeout(800); await p.screenshot({ path: `${OUT}/${sn}-${scheme}-settings.png` });
  console.log(sn, scheme, 'overflow:', await p.evaluate(() => document.documentElement.scrollWidth > innerWidth)); await ctx.close();
}
await b.close();
