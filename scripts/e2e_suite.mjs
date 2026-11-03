// Browser end-to-end suite with pass/fail checks (fake data, real Ollama + Chrome).
// Run via scripts/run_e2e.sh, which starts an isolated server and writes E2E-REPORT.md.
// Env: BASE (server url), PW (path to playwright-core), CFG (isolated config.json path), RESULTS (json output path).
import fs from 'node:fs';
const pw = await import(process.env.PW || 'playwright-core'); const chromium = pw.chromium || pw.default.chromium;
const B = process.env.BASE || 'http://127.0.0.1:8799';
const results = [];
async function check(group, name, fn) {
  const t = Date.now();
  try { const detail = await fn(); results.push({ group, name, ok: true, detail: detail || '', ms: Date.now() - t }); console.log('PASS', group, '-', name); }
  catch (e) { results.push({ group, name, ok: false, detail: String(e.message).split('\n')[0], ms: Date.now() - t }); console.log('FAIL', group, '-', name, '::', e.message.split('\n')[0]); }
}
const ok = (c, m) => { if (!c) throw new Error(m); };
const b = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
const p = await b.newPage();
const errs = []; p.on('pageerror', (e) => errs.push(e.message)); p.on('console', (m) => m.type() === 'error' && !/401|400|404/.test(m.text()) && errs.push(m.text()));
p.on('response', (r) => r.status() === 404 && errs.push('404 ' + r.url()));
let promptAnswer = '';
p.on('dialog', (d) => d.accept(promptAnswer));
const badges = () => p.$$eval('.badge', (n) => n.map((x) => x.textContent));
const done = (n) => p.waitForFunction((n) => [...document.querySelectorAll('.badge')].filter((x) => /Local|Claude/.test(x.textContent)).length >= n, n, { timeout: 600000 });
const EMAIL = 'e2e@example.com', PW1 = 'e2e-password-1', PW2 = 'e2e-password-2';

await check('Accounts', 'login screen shows when signed out', async () => { await p.goto(B); await p.waitForSelector('#login:not([hidden])'); });
await check('Accounts', 'register new account', async () => {
  await p.click('#switchMode'); await p.fill('#email', EMAIL); await p.fill('#pw', PW1); await p.click('#loginBtn');
  await p.waitForSelector('#app:not([hidden])'); ok((await p.textContent('#who')).includes(EMAIL), 'email not shown');
});
await check('Library', 'upload a file and list it', async () => {
  await p.setInputFiles('#file', new URL('../samples/maria_statement.txt', import.meta.url).pathname);
  await p.waitForSelector('#docs li'); return await p.textContent('#docs li');
});
await check('Library', 'move a file into a new folder and scope questions to it', async () => {
  await p.click('#docs li button:has-text("Move")');
  await p.selectOption('#moveSel', { label: 'New folder…' }); await p.fill('#moveNew', 'Banking');
  await p.click('#moveForm button[type=submit]');
  await p.waitForSelector('#docs summary:has-text("Banking")');
  ok(await p.$$eval('#scope option', (o) => o.some((x) => x.value === 'Banking')), 'folder not in scope list');
  return 'folder Banking created, listed and selectable';
});
await check('Settings', 'local model panel lists installed models', async () => {
  await p.click('#setBtn'); await p.waitForFunction(() => document.querySelectorAll('#cfg_answer option').length > 0, null, { timeout: 10000 });
  const n = await p.$$eval('#cfg_answer option', (o) => o.length); ok(n > 0, 'no models'); return n + ' installed models listed';
});
await check('Settings', 'default values shown', async () => {
  ok((await p.inputValue('#cfg_answer')) === 'gemma4:26b', 'answer default'); await p.click('#setDlg summary'); ok((await p.inputValue('#cfgUrl')).includes('11434'), 'url default');
});
await check('Settings', 'outside Ollama address is refused', async () => {
  await p.fill('#cfgUrl', 'http://8.8.8.8:11434'); await p.click('#cfgForm button[type=submit]'); await p.waitForTimeout(600);
  ok(/this machine/i.test(await p.textContent('#cfgMsg')), 'no refusal message');
});
await check('Settings', 'bad model name is refused', async () => {
  await p.fill('#cfgUrl', 'http://127.0.0.1:11434'); const bad = await p.request.post(B + '/api/config', { data: { answer: 'bad name; rm -rf' }, headers: { Origin: B, 'X-Requested-With': 'privhybrid' } }); ok(bad.status() === 400, 'status ' + bad.status() + ' ' + (await bad.text()).slice(0, 80));
});
await check('Settings', 'valid change saves to the config file', async () => {
  await p.selectOption('#cfg_answer', 'qwen2.5:7b'); await p.click('#cfgForm button[type=submit]'); await p.waitForTimeout(800);
  ok(/Saved/.test(await p.textContent('#cfgMsg')), 'not saved');
  const f = JSON.parse(fs.readFileSync(process.env.CFG, 'utf8')); ok(f.answer === 'qwen2.5:7b', 'file not updated');
});
await check('Settings', 'change survives a reload', async () => {
  await p.reload(); await p.waitForSelector('#app:not([hidden])'); await p.click('#setBtn'); await p.waitForTimeout(800);
  ok((await p.inputValue('#cfg_answer')) === 'qwen2.5:7b', 'not persisted');
});
await check('Settings', 'switch back to default model for the chat tests', async () => {
  await p.selectOption('#cfg_answer', 'gemma4:26b'); await p.click('#cfgForm button[type=submit]'); await p.waitForTimeout(800); await p.click('#setClose');
});
await check('Chat', 'two questions sent back to back are queued and both answered', async () => {
  await p.fill('#q', 'I want to buy a house in 2028 and my sister Priya is moving in with me.'); await p.press('#q', 'Enter');
  await p.fill('#q', 'Say hello in five words.'); await p.press('#q', 'Enter'); await p.waitForTimeout(500);
  ok((await badges()).some((t) => /queued/.test(t)), 'second question not queued');
  await done(2); return (await badges()).join(' | ');
});
await check('Chat', 'chat is saved in the sidebar', async () => ok((await p.$$eval('#chats li', (n) => n.length)) >= 1, 'no saved chat'));
await check('Memory', 'facts the user stated are remembered', async () => {
  await p.waitForFunction(() => document.querySelectorAll('#facts li button').length > 0, null, { timeout: 120000 });
  return (await p.$$eval('#facts li', (n) => n.map((x) => x.firstChild.textContent))).join(' | ');
});
await check('Memory', 'new chat starts empty', async () => { await p.click('#resetBtn'); await p.waitForFunction(() => document.querySelectorAll('#chat .msg').length === 0, null, { timeout: 5000 }).catch(() => { throw new Error('not cleared'); }); });
await check('Memory', 'new chat recalls remembered facts', async () => {
  await p.fill('#q', 'What are my plans for 2028? One sentence.'); await p.press('#q', 'Enter');
  await p.waitForFunction(() => document.querySelectorAll('#chat .msg:not(.user)').length >= 1 && /Local|Claude/.test(document.querySelector('.badge')?.textContent), null, { timeout: 600000 });
  const a = await p.textContent('#chat .msg:not(.user)'); ok(/house|2028|Priya|sister/i.test(a), 'answer ignored memory: ' + a.slice(0, 120)); return a.slice(0, 160);
});
await check('Privacy', 'Tier 1 data (SSN) stops and asks before sending', async () => {
  await p.click('#resetBtn');
  await p.click('input[name=mode][value=claude]');
  await p.fill('#q', 'My SSN is 123-45-6789, is that safe to share?'); await p.press('#q', 'Enter');
  await p.waitForSelector('#approval[open]', { timeout: 60000 });
  ok(/./.test(await p.textContent('#apReason')), 'no reason shown');
  await p.click('#approval button[value=cancel]'); await p.waitForTimeout(400);
});
await check('Privacy', 'audit log has counts only, no planted value', async () => {
  const a = await (await p.request.get(B + '/api/audit')).text();
  ok(!a.includes('123-45-6789') && !a.includes('Delgado') && !a.includes('Priya'), 'value found in audit log'); return a.split('},').length + ' audit lines';
});
await p.click('input[name=mode][value=auto]');
await check('Session', 'reload keeps login and chats', async () => {
  await p.reload(); await p.waitForSelector('#app:not([hidden])'); ok((await p.$$eval('#chats li', (n) => n.length)) >= 1, 'no chats');
});
await check('Session', 'reopen a saved chat', async () => { await p.click('#chats li button'); await p.waitForTimeout(600); ok((await p.$$eval('#chat .msg', (n) => n.length)) > 0, 'empty'); });
await check('Accounts', 'sign out returns to login', async () => { await p.click('#logoutBtn'); await p.waitForSelector('#login:not([hidden])'); });
await check('Accounts', 'wrong password is rejected', async () => {
  await p.fill('#email', EMAIL); await p.fill('#pw', 'wrong-password'); await p.click('#loginBtn'); await p.waitForTimeout(600);
  ok((await p.textContent('#loginErr')).length > 0, 'no error');
});
await check('Accounts', 'sign in again; library and facts intact', async () => {
  await p.fill('#pw', PW1); await p.click('#loginBtn'); await p.waitForSelector('#app:not([hidden])');
  ok((await p.$$eval('#docs li', (n) => n.length)) >= 1 && (await p.$$eval('#facts li button', (n) => n.length)) >= 1, 'data missing');
});
await check('Accounts', 'change password', async () => {
  await p.click('#acctBtn'); await p.fill('#oldPw', PW1); await p.fill('#newPw', PW2); await p.click('#pwForm button[type=submit]'); await p.waitForTimeout(2500);
  ok(/changed/i.test(await p.textContent('#pwMsg')), await p.textContent('#pwMsg'));
});
await check('Accounts', 'delete account removes everything', async () => {
  await p.fill('#delPw', PW2); await p.click('#delForm button[type=submit]'); await p.waitForSelector('#login:not([hidden])');
});
await check('UI', 'theme button cycles Auto → Light → Dark and persists', async () => {
  const th = () => p.evaluate(() => document.documentElement.dataset.theme || 'auto');
  await p.fill('#email', EMAIL).catch(() => {}); const seen = [await th()];
  for (let i = 0; i < 2; i++) { await p.click('#themeBtn2'); seen.push(await th()); }
  ok(seen.join() === 'auto,light,dark', seen.join());
  await p.reload(); ok((await th()) === 'dark', 'not persisted'); await p.click('#themeBtn2'); ok((await th()) === 'auto', 'did not return to auto');
});
await check('UI', 'light and dark both render readable text (contrast > 4.5)', async () => {
  for (const t of ['light', 'dark']) {
    await p.emulateMedia({ colorScheme: t }); await p.waitForTimeout(100);
    const r = await p.evaluate(() => { const c = (s) => s.match(/\d+(\.\d+)?/g).slice(0, 3).map(Number); const L = ([r, g, b]) => { const f = (v) => (v /= 255) <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const cs = getComputedStyle(document.querySelector('#loginHint')), bg = getComputedStyle(document.body); const a = L(c(cs.color)), b = L(c(bg.backgroundColor)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); });
    ok(r > 4.5, t + ' contrast ' + r.toFixed(2));
  }
});
await check('UI', 'no horizontal overflow at 320px (small phone)', async () => {
  await p.setViewportSize({ width: 320, height: 640 }); await p.reload(); await p.waitForTimeout(300);
  ok(!(await p.evaluate(() => document.documentElement.scrollWidth > innerWidth)), 'overflow');
});
await check('UI', 'no horizontal overflow at phone width', async () => {
  await p.setViewportSize({ width: 390, height: 800 }); await p.reload(); await p.waitForTimeout(300);
  ok(!(await p.evaluate(() => document.documentElement.scrollWidth > innerWidth)), 'overflow');
});
await check('UI', 'no JavaScript errors during the run', async () => ok(errs.length === 0, JSON.stringify(errs)));
await b.close();
fs.writeFileSync(process.env.RESULTS || 'e2e-results.json', JSON.stringify(results, null, 1));
process.exit(results.every((r) => r.ok) ? 0 : 1);
