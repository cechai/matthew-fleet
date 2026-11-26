// converter2.mjs - rebuild the runner keystore from the encrypted keystores.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
const KSDIR = process.env.KSDIR || (process.env.HOME + '/.dsh/skills/wallet/keystores');
const OUT = process.env.OUT || (process.env.HOME + '/.dsh/skills/wallet/fleet.json');
const SIG_HEX = 'bea79aea1bf48b9d9538e53bfa698044405ff4cdbb03e019232f1f7618e90df839c11a5e2e77107facdc57227f70a6fea47e060aa9eb267798abe000df8be16d1c';
const KEY = crypto.createHash('sha256').update(Buffer.from(SIG_HEX,'hex')).digest();
const wallets = [];
for (const label of ['f1','f2','f3','f4','f5','f6']) {
  const e = JSON.parse(fs.readFileSync(KSDIR + '/' + label + '.json','utf8'));
  const dec = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(e.iv,'hex'));
  dec.setAuthTag(Buffer.from(e.tag,'hex'));
  let p = dec.update(e.encryptedPrivateKey,'hex','hex');
  p += dec.final('hex');
  const acct = privateKeyToAccount('0x' + p);
  if (acct.address.toLowerCase() !== e.address.toLowerCase()) { console.error('MISMATCH ' + label); process.exit(1); }
  wallets.push({ label, address: e.address, privHex: '0x'+p, balanceWei: '0', spentWei: '0', trades: 0, firstSeen: null });
}
fs.writeFileSync(OUT, JSON.stringify({ v:1, createdAt: new Date().toISOString(), chainId:16661, wallets }, null, 1), { mode:0o600 });
console.log('wrote ' + wallets.length + ' wallets to ' + OUT);
for (const w of wallets) console.log(w.label, w.address);
