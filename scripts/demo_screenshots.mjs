// README screenshots from a throwaway demo server (fake data only). Usage: BASE=http://127.0.0.1:8791 OUT=docs/screenshots PW=... node scripts/demo_screenshots.mjs
// Start the server first: PRIVHYBRID_DEMO=1 serve(port=8791, data_dir/audit_path in a temp dir). The demo account is the first, so it sees Activity.
const { chromium } = await import(process.env.PW || 'playwright-core');
const B = process.env.BASE || 'http://127.0.0.1:8791', OUT = process.env.OUT || 'docs/screenshots';
const b = await chromium.launch({ channel: 'chrome' });
const p = await (await b.newContext({ viewport: { width: 1200, height: 760 }, deviceScaleFactor: 2, colorScheme: 'light' })).newPage();
try {
await p.goto(B + '/demo'); await p.waitForSelector('#docs li', { state: 'attached', timeout: 120000 });
await p.waitForTimeout(500); await p.screenshot({ path: `${OUT}/1-library.png` });
const ask = async (q, mode) => {
  await p.check(`input[name=mode][value=${mode}]`); await p.fill('#q', q); await p.press('#q', 'Enter');
};
await ask('What filing status and allowances are on my W-4?', 'local');
await p.waitForSelector('.msg:not(.user) .md', { timeout: 300000 }); await p.waitForFunction(() => !document.querySelector('.flow .active'), null, { timeout: 300000 });
await p.screenshot({ path: `${OUT}/2-local-answer.png` });
await p.click('#resetBtn'); await p.waitForTimeout(500);
await ask('Summarise my W-4 and bank statement for Claude', 'claude');
await p.waitForSelector('#approval[open]', { timeout: 300000 }); await p.waitForTimeout(600);
await p.screenshot({ path: `${OUT}/3-stopped.png` });
await p.click('#approval button[value=cancel]'); await p.waitForTimeout(500);
await p.click('#auditBtn'); await p.waitForTimeout(900); await p.evaluate(() => { document.getElementById('auditDlg').scrollTop = 0; });
await p.screenshot({ path: `${OUT}/4-activity.png` });
} finally { await b.close(); }
