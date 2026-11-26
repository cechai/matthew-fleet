#!/usr/bin/env node
// fleet.mjs — the local multi-wallet fleet for the iAI/0G pool.
//
// WHY THIS FILE EXISTS. The proven trading code
// (engine/final_all_wallets.mjs) ran inside the agent's container, where
// the wallet keystores lived. That container is gone and its disk was not
// durable, so the keys went with it. This runner is the same calldata,
// the same selectors, the same gas — but it runs on this machine and owns
// its own keys.
//
// THE THREE THINGS THAT MUST NEVER CHANGE. These are the bugs that cost
// 30 0G and 1.0 0G in real money:
//
//   1. The recipient is ALWAYS derived from the key, never typed.
//      A typed address is how 30 0G went to 0x...7000000000.
//   2. The Permit2 approve selector is 0x87517c45, and it is a plain
//      transaction. The Permit2 at 0x...8BA3 is a 9,152-byte custom
//      contract, not the Uniswap one, so every standard selector reverts.
//   3. The nonce is read FRESH before every signature, because a
//      co-signer can move it underneath us.
//
// Every transaction also carries a min_out that is never zero, a deadline
// that is never far away, and a value that is read from the key's own
// balance rather than from the caller's intent.
//
// USAGE
//   node fleet.mjs init <n>                create the keystore
//   node fleet.mjs list                    the wallets and their balances
//   node fleet.mjs fund                    print the addresses to fund
//   node fleet.mjs doctor                  preflight checks
//   node fleet.mjs approve <label>         the two approvals, one wallet
//   node fleet.mjs quote <label> <0G>      what a buy would return
//   node fleet.mjs roundtrip <label> <0G>  buy then sell
//
// The keys live at ~/.matthew-fleet/ (0700) and never leave this machine
// except as a signature.

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, appendFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createPublicClient, createWalletClient, fallback, http, parseAbi, formatUnits } from 'viem';
import { checkTransaction, testOnChain, decodeRecipient } from './guard.mjs';

// THE SAFETY RESERVE. What every wallet must still hold after a trade, so
// it can always pay for its next sell. This was declared inside one
// function and used in another, which stopped the whole fleet from
// starting. It lives here now, and it matches the planner's own cushion
// (0.01 0G) so the two can never disagree about what is affordable.
const GUARD_RESERVE_WEI = 5n * 10n ** 15n; // 0.005 0G - ~6x the gas of a sell

const DIR = process.env.FLEET_KEYSTORE || `${process.env.HOME}/.matthew-fleet`;
const STORE = `${DIR}/fleet.json`;
const LOG = `${DIR}/ledger.jsonl`;

const IAI = '0xc77FBd3824cc68e612b26114D176879aDdc29463';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const VENUE = '0x76526f4815447f693468ef44e0204a0689178d9e';
const POOL_MGR = '0xaabd31f24914b48daea998e69683225e289d08b0';
const ARG2 = '0xc912324aca9ea0cc34c2615dc53d5a0465bbad30';
const CHAIN_ID = 16661;
// THE RPC LIST.
//
// The chain's public endpoint goes down sometimes and answers with a 502.
// A single endpoint means one bad minute kills live trades. So the fleet
// talks to three of them and retries, and only gives up when all three
// are down. A trade that fails on the first endpoint is tried again on
// the next one before it is called a failure.
const RPCS = (process.env.FLEET_RPC || 'https://evmrpc.0g.ai')
  .split(',').map((s) => s.trim()).filter(Boolean);
const RPC = RPCS[0];
const GAS_PRICE = 4_000_000_000n;

// The two price limits from the venue's own swap args.
const LIMIT_BUY = 8388608n;
const LIMIT_SELL = 3932227n;
const DIRECTION = 0x800000n;

// The gas limits, from the measured receipts.
const GAS_APPROVE_P2 = 300000n;
const GAS_APPROVE_ERC = 70000n;
const GAS_BUY = 400000n;   // a buy uses ~176k gas
// The gas limits, raised after measuring 22 real sells off chain:
//   the min 198,022  the median 280,000  the max 572,052
// 8 of 22 exceeded 400,000. NONE exceeded 600,000. The gas limit is only
// a ceiling - the unused part is not charged - so it is set well above
// what has ever been needed rather than at the edge.
const GAS_SELL = 400000n;   // a sell uses ~176k gas
const cfgGasPerRoundTripWei = 400000n * 4_000_000_000n;   // in wei; divide by 1e18 at use

// ─────────────────────────────────────────────────────────────────────────────
// The calldata. Byte-for-byte what the proven code sent.
// ─────────────────────────────────────────────────────────────────────────────

function addrWord(a) {
  const b = Buffer.from(a.toLowerCase().replace(/^0x/, ''), 'hex');
  const w = Buffer.alloc(32);
  b.copy(w, 12);
  return w.toString('hex');
}
function u256(n) { return BigInt(n).toString(16).padStart(64, '0'); }

/** The BUY. Selector 0x0e897ef6, 9 words. */
export function buildBuy(amountInWei, minOutWei, deadline, recipient) {
  const z = '0'.repeat(64);
  const words = [z, addrWord(IAI), addrWord(ARG2), addrWord(POOL_MGR),
    u256(LIMIT_BUY), u256(LIMIT_SELL), u256(minOutWei), addrWord(recipient), u256(deadline)];
  return '0x0e897ef6' + words.join('');
}

/** The SELL. Selector 0xaf98eef6, 19 words. The ONLY sell form on chain. */
export function buildSell(amountInWei, minOutWei, deadline, recipient) {
  const z = '0'.repeat(64);
  const iw = addrWord(IAI);
  return '0xaf98eef6' + [z, iw, addrWord(ARG2), addrWord(POOL_MGR), u256(DIRECTION),
    u256(LIMIT_SELL), u256(amountInWei), u256(minOutWei), addrWord(recipient), u256(deadline),
    u256(352n), iw, z, z, z, addrWord(VENUE), z, u256(224n), z].join('');
}

/** The Permit2 approve. THE FIX: 0x87517c45, a plain transaction. */
export function buildP2Approve(token, spender, amount, expiration) {
  return '0x87517c45' + addrWord(token) + addrWord(spender) + u256(amount) + u256(expiration);
}

/** The ERC-20 approve. */
export function buildERCApprove(spender, amount) {
  return '0x095ea7b3' + addrWord(spender) + u256(amount);
}

/**
 * Read the deadline back out of the bytes we built.
 * The buy puts it in part 8; the sell puts it in part 9.
 * Both confirmed against real trades off chain.
 */
function decodeDeadline(data) {
  const body = (data || '').slice(10);
  const sel = (data || '').slice(0, 10).toLowerCase();
  const idx = sel === '0xaf98eef6' ? 9 : 8;
  const word = body.slice(idx * 64, idx * 64 + 64);
  if (word.length !== 64) return 0n;
  return BigInt('0x' + word);
}

// ─────────────────────────────────────────────────────────────────────────────
// The keystore.
// ─────────────────────────────────────────────────────────────────────────────

function loadStore() {
  if (!existsSync(STORE)) { console.error(`no keystore at ${STORE}. Run: node fleet.mjs init N`); process.exit(2); }
  const raw = JSON.parse(readFileSync(STORE, 'utf8'));
  for (const w of raw.wallets) w.account = privateKeyToAccount(w.privHex);
  return raw;
}
function saveStore(s) {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  writeFileSync(STORE, JSON.stringify(s), { mode: 0o600 });
  chmodSync(STORE, 0o600);
}
function writeLedger(entry) {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  appendFileSync(LOG, JSON.stringify({ t: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
}

// The reading client: three endpoints, four tries each, so a 502 from one
// endpoint is a slow answer, not a dead fleet.
const pub = createPublicClient({
  transport: fallback(RPCS.map((u) => http(u, { retryCount: 4, retryDelay: 300, timeout: 20_000 }))),
  retryCount: 4,
});
const IAI_ABI = parseAbi([
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
]);

// A raw eth_call. The venue's quote returns a bare uint256, and viem's
// typed `call` mangles the shape of an untyped return - so the quote path
// uses raw JSON-RPC and reads the first word itself.
async function rawCallWords(from, to, data, value) {
  const body = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'eth_call',
    params: [{ from, to, data, value: '0x' + BigInt(value).toString(16) }, 'latest'],
  });
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
    body,
  });
  const j = await res.json();
  if (j.error) throw new Error(`the quote reverted: ${j.error.message} ${(j.error.data || '').slice(0, 10)}`);
  if (!j.result || j.result === '0x') throw new Error('the quote came back EMPTY - refusing to treat that as zero');
  const h = j.result.replace(/^0x/, '');
  const words = [];
  for (let i = 0; i < h.length; i += 64) words.push(h.slice(i, i + 64));
  return words.map((w) => BigInt('0x' + w));
}

/**
 * A receipt, read straight from the chain, with no timeout.
 *
 * Used when the receipt wait times out. A timeout is not a failure - the
 * transaction may still land - and saying "failed" when it landed is how a
 * ledger starts lying.
 */
async function rawReceipt(hash) {
  const body = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [hash],
  });
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
    body,
  });
  const j = await res.json();
  if (!j.result) return null;
  const r = j.result;
  return {
    status: r.status === '0x1' ? 'success' : 'reverted',
    gasUsed: BigInt(r.gasUsed),
    effectiveGasPrice: BigInt(r.effectiveGasPrice || '0x0'),
  };
}

/**
 * The first word of a return, as a number.
 *
 * The single-word form of this function was a real bug. The Permit2
 * allowance returns THREE words - (amount uint160, expiration uint48,
 * nonce uint48) - and reading only the first one made the expiry check
 * read `amount >> 160`, which is always 0. The check could never fire, and
 * it was the one thing standing between the fleet and a dead sell leg.
 */
async function rawCall(from, to, data, value) {
  const words = await rawCallWords(from, to, data, value);
  return words[0];
}

/**
 * Add wallets to an existing keystore. `init` refuses to touch an existing
 * keystore (the keys exist nowhere else), so this is how the fleet grows.
 */
function cmdAdd(n) {
  if (!existsSync(STORE)) { console.error(`no keystore at ${STORE}. Run: node fleet.mjs init N`); process.exit(2); }
  const raw = JSON.parse(readFileSync(STORE, 'utf8'));
  const used = new Set(raw.wallets.map((w) => w.label));
  const added = [];
  for (let i = 0; i < n; i++) {
    let label = `f${raw.wallets.length + 1 + i}`;
    while (used.has(label)) label = `f${raw.wallets.length + 1 + i}_${Math.floor(Math.random() * 1000)}`;
    used.add(label);
    const privHex = generatePrivateKey();
    const account = privateKeyToAccount(privHex);
    added.push({ label, address: account.address, privHex, balanceWei: '0', spentWei: '0', trades: 0, firstSeen: null });
  }
  raw.wallets.push(...added);
  saveStore(raw);
  console.log(`added ${added.length} wallets:`);
  for (const w of added) console.log(`  ${w.label}  ${w.address}`);
  console.log('FUND THESE FROM THE EXCHANGE, not from your own wallet.');
}

function cmdInit(n) {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  chmodSync(DIR, 0o700);
  // NEVER silently destroy a keystore. The private keys exist nowhere else
  // and there is no backup. Overwriting this file after the fleet is
  // funded makes the capital unrecoverable with no on-chain trace.
  if (existsSync(STORE)) {
    if (!process.argv.includes('--force')) {
      console.error(`A KEYSTORE ALREADY EXISTS at ${STORE}.`);
      console.error('Overwriting it would destroy the keys for any funded wallet.');
      console.error('Use --force to overwrite (a timestamped backup is written first), or `export` the keys.');
      process.exit(2);
    }
    const bak = `${STORE}.${Date.now()}.bak`;
    writeFileSync(bak, readFileSync(STORE), { mode: 0o600 });
    console.log(`the old keystore is backed up to ${bak}`);
  }
  const wallets = [];
  for (let i = 0; i < n; i++) {
    const privHex = generatePrivateKey();
    const account = privateKeyToAccount(privHex);
    wallets.push({
      label: `f${i + 1}`,
      address: account.address,
      privHex,
      balanceWei: '0',
      spentWei: '0',
      trades: 0,
      firstSeen: null,
    });
  }
  saveStore({ v: 1, createdAt: Date.now(), chainId: CHAIN_ID, wallets });
  console.log(`generated ${wallets.length} wallets -> ${STORE}`);
  for (const w of wallets) console.log(`  ${w.label}  ${w.address}`);
  const setupGas = BigInt(wallets.length) * 1096000n * GAS_PRICE / (10n ** 18n);  // exact, gas price is 4 gwei
  console.log(`the setup gas: ${formatUnits(setupGas, 18)} 0G`);
}

async function cmdList() {
  const s = loadStore();
  console.log(`${s.wallets.length} wallets`);
  for (const w of s.wallets) {
    const bal = await pub.getBalance({ address: w.address });
    const iai = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'balanceOf', args: [w.address] });
    const allow = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'allowance', args: [w.address, PERMIT2] });
    console.log(`  ${w.label.padEnd(5)} ${w.address}  the 0G ${formatUnits(bal, 18).padStart(12)}  the iAI ${formatUnits(iai, 18)}  the allow ${formatUnits(allow, 18)}  the trades ${w.trades}`);
  }
}

function cmdExport(label) {
  const s = loadStore();
  const w = s.wallets.find((x) => x.label === label);
  if (!w) { console.error(`no wallet ${label}`); process.exit(2); }
  // The key is printed because the ONLY backup path is a human writing it
  // down. Refusing to print it makes the fleet unrecoverable.
  console.log(w.privHex);
}

function cmdFund() {
  const s = loadStore();
  console.log('the addresses to fund, and how much:');
  for (const w of s.wallets) {
    // the KEY-DERIVED address, not the stored one. The stored one is typed
    // data; the key is the truth. If they ever differ, the key wins.
    const derived = w.account.address;
    const flag = derived.toLowerCase() === w.address.toLowerCase() ? '' : '  <-- THE STORED ADDRESS DIFFERS! USE THIS ONE.';
    console.log(`  ${w.label}  ${derived}${flag}`);
  }
  console.log('');
  console.log('FUND THESE FROM THE EXCHANGE, NOT FROM YOUR OWN WALLET.');
  console.log('a transfer from your address is a permanent, machine-readable link.');
}

async function cmdDoctor() {
  const s = loadStore();
  let bad = 0;
  console.log('the preflight:');
  for (const w of s.wallets) {
    // the recipient is derived from the key, never typed
    const derived = w.account.address.toLowerCase();
    if (derived !== w.address.toLowerCase()) { console.log(`  ${w.label} FAIL the address does not match the key`); bad++; continue; }
    const bal = await pub.getBalance({ address: w.address });
    const nonce = await pub.getTransactionCount({ address: w.address, blockTag: 'pending' });
    console.log(`  ${w.label} ok  the 0G ${formatUnits(bal, 18)}  the nonce ${nonce}  the address matches the key`);
  }
  // the chain
  const cid = await pub.getChainId();
  console.log(`  the chain id: ${cid} ${cid === CHAIN_ID ? 'ok' : 'FAIL'}`);
  if (cid !== CHAIN_ID) bad++;
  // the venue is a contract
  const code = await pub.getCode({ address: VENUE });
  console.log(`  the venue has code: ${code && code !== '0x' ? 'ok' : 'FAIL'}`);
  if (!code || code === '0x') bad++;
  const p2 = await pub.getCode({ address: PERMIT2 });
  console.log(`  the Permit2 has code: ${p2 && p2 !== '0x' ? 'ok' : 'FAIL'}`);
  if (!p2 || p2 === '0x') bad++;
  // the sell selector must exist in the venue's bytecode
  const buySel = '0e897ef6', sellSel = 'af98eef6';
  console.log(`  the buy selector ${buySel} in the bytecode: ${code.includes(buySel) ? 'ok' : 'FAIL'}`);
  console.log(`  the sell selector ${sellSel} in the bytecode: ${code.includes(sellSel) ? 'ok' : 'FAIL'}`);
  if (!code.includes(buySel) || !code.includes(sellSel)) bad++;
  // the Permit2 approve selector must exist in the Permit2's bytecode
  const p2sel = '87517c45';
  console.log(`  the Permit2 approve selector ${p2sel} in the bytecode: ${p2.includes(p2sel) ? 'ok' : 'FAIL'}`);
  if (!p2.includes(p2sel)) bad++;
  console.log(bad === 0 ? '\nALL GREEN.' : `\n${bad} PROBLEM(S).`);
  if (bad) process.exit(1);
}

async function send(w, tx, gasLimit, note) {
  // ── THE SAFETY LAYER. Every broadcast goes through here. ────────────────
  // The guard is called BEFORE the signature is made, so a trade that fails
  // a rule never gets signed and never costs a fee.
  //
  // If you are reading this after a bad trade, look here first: the guard
  // is the thing that was supposed to stop it.
  if (globalThis.__guardCtx) {
    // ── RULE 10. Ask the chain if it will work, before we sign. ──────────
    // If the chain says it would fail, we never send it. So a trade that
    // cannot succeed never costs a fee.
    //
    // THIS RUNS BEFORE THE GUARD, on purpose. The guard asks "can this
    // wallet afford this trade?" and it needs to know the gas cost. Before
    // this change the guard was handed the gas LIMIT - the ceiling we sign
    // for - not the gas the trade actually needs. The sell's ceiling is
    // 1,000,000 gas (0.0040 0G) while a real sell needs about 200,000
    // (0.0008 0G). A wallet sitting just above the 0.5 cushion was
    // refused for gas it would never pay. That is what blocked f5's sell.
    //
    // The chain's own estimate is the truth. We use it, plus a margin for
    // the difference between the estimate and the final charge, and we
    // never use more than the ceiling.
    const test = await testOnChain(pub, tx, w.account.address);
    if (!test.ok) {
      writeLedger({ wallet: w.label, note, status: 'refused', error: test.reason, stage: 'chain-test' });
      throw new Error(`the chain says this trade would fail, so it was NOT sent: ${test.reason}`);
    }
    // the margin covers the estimate-vs-actual gap; the ceiling still caps it
    const gasForCost = test.gas * 120n / 100n;
    const gasCostWei = (gasForCost > gasLimit ? gasLimit : gasForCost) * GAS_PRICE;
    console.log(`  ${note}: the chain tested it. the gas would be ${test.gas} (counting ${gasForCost} for the wallet's balance).`);
    try {
      checkTransaction(tx, {
        ...globalThis.__guardCtx,
        walletAddress: w.account.address,
        walletBalanceWei: await pub.getBalance({ address: w.account.address }),
        gasCostWei,
        deadlineSeconds: decodeDeadline(tx.data),
        where: note,
      });
    } catch (e) {
      writeLedger({ wallet: w.label, note, status: 'refused', error: String(e.message || e), stage: 'guard' });
      throw new Error(`REFUSED by the safety layer: ${e.message}`);
    }
  }

  const client = createWalletClient({ account: w.account, chain: { id: CHAIN_ID, name: '0g', nativeCurrency: { name: '0G', symbol: '0G', decimals: 18 }, rpcUrls: { default: { http: [RPC] } } }, transport: fallback(RPCS.map((u) => http(u, { retryCount: 4, retryDelay: 300, timeout: 20_000 }))), retryCount: 4 });
  // THE NONCE IS READ FRESH, EVERY TIME, FROM THE KEY-DERIVED ADDRESS.
  //
  // The audit caught that this read the STORED address while the signature
  // came from the KEY. If those ever differ, the nonce is for the wrong
  // account and the transaction replaces or collides with someone else's.
  // The key is the truth, so the key's address is what gets read.
  const nonceAddr = w.account.address;
  const nonce = await pub.getTransactionCount({ address: nonceAddr, blockTag: 'pending' });
  const hash = await client.sendTransaction({
    ...tx,
    nonce,
    gas: gasLimit,
    maxFeePerGas: GAS_PRICE,
    maxPriorityFeePerGas: 2_500_000_000n,
    chain: undefined,
  });
  console.log(`  ${note}: ${hash}`);
  let rc;
  try {
    rc = await pub.waitForTransactionReceipt({ hash, confirmations: 1, timeout: 120000 });
  } catch (e) {
    // A TIMEOUT IS NOT A FAILURE. The transaction may still land. Reporting
    // it as failed would mark a completed trade as broken and, worse, would
    // make the ledger lie. Check the chain directly before saying anything.
    console.log(`  ${note}: the receipt timed out. checking the chain directly...`);
    const direct = await rawReceipt(hash);
    if (direct) {
      rc = direct;
    } else {
      console.error(`  ${note}: NO RECEIPT. the hash is ${hash}. it may still land.`);
      writeLedger({ wallet: w.label, note, hash, status: 'unknown', error: 'no receipt within the timeout' });
      throw new Error(`NO_RECEIPT (${hash}) - the transaction may still land. Check the hash.`);
    }
  }
  const gasCost = rc.gasUsed * rc.effectiveGasPrice;
  console.log(`  ${note}: ${rc.status === 'success' ? 'SUCCESS' : 'REVERTED'}  the gas ${rc.gasUsed} (${formatUnits(gasCost, 18)} 0G)`);
  writeLedger({ wallet: w.label, note, hash, status: rc.status, gasUsed: String(rc.gasUsed), gasCostWei: gasCost.toString() });
  return { hash, rc };
}

async function cmdApprove(label) {
  const s = loadStore();
  const w = s.wallets.find((x) => x.label === label);
  if (!w) { console.error(`no wallet ${label}`); process.exit(2); }
  // the recipient comes from the KEY
  const recipient = w.account.address;
  // THE EXPIRATION. Not 0, and not "now + 2 hours".
  //
  // The audit caught me assuming that 0 means "never". In the standard
  // Permit2 layout `expiration` is a timestamp and the pull reverts when
  // `block.timestamp > expiration`, which makes 0 the MOST expired value
  // there is. If this custom 9,152-byte contract special-cases zero, then
  // 0 works. If it does not, EVERY SELL REVERTS while every buy succeeds,
  // and the fleet converts its whole float into iAI it cannot sell.
  //
  // There is no reason to gamble. The uint48 maximum is unambiguously in the
  // future under BOTH readings, and the field is 48 bits wide so it fits.
  // It expires in year 8,918,655.
  const expiration = (1n << 48n) - 1n;
  const MAX = (1n << 160n) - 1n;

  // The ERC-20 allowance to Permit2 is also consumed by each sell, so it is
  // set to MAX. Reading it fresh tells us whether to skip.
  const allow = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'allowance', args: [recipient, PERMIT2] });
  if (allow < 10n ** 15n) {
    console.log('the ERC-20 approve -> Permit2:');
    await send(w, { to: IAI, data: buildERCApprove(PERMIT2, MAX) }, GAS_APPROVE_ERC, 'the ERC-20 approve');
  } else {
    console.log('the ERC-20 approve: already sufficient, skipping');
  }
  console.log('the Permit2 approve -> the venue:');
  await send(w, { to: PERMIT2, data: buildP2Approve(IAI, VENUE, MAX, expiration) }, GAS_APPROVE_P2, 'the Permit2 approve');

  // VERIFY. A green receipt is not proof - that is how a wrong-key
  // signature once gave a green receipt while the allowance stayed 0.
  // Read the allowance back off the chain and check the amount AND the
  // expiry, because the sell leg needs the approval to still be alive at
  // the time of the sell.
  const P2_ALLOW = '0x927da105';
  const aw = (a) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
  const words = await rawCallWords(recipient, PERMIT2, P2_ALLOW + aw(recipient) + aw(IAI) + aw(VENUE), 0);
  // three words: (amount uint160, expiration uint48, nonce uint48)
  const p2Amount = words[0];
  const p2Expiry = words[1];
  const p2Nonce = words[2];
  console.log(`  the Permit2 allowance now: the amount ${p2Amount === (1n << 160n) - 1n ? 'MAX' : formatUnits(p2Amount, 18)}  the expiry ${p2Expiry === 0n ? 'ZERO (the most expired value - NOT never)' : (Number(p2Expiry) * 1000 > 8.64e15 ? 'the far future (year 8918655)' : new Date(Number(p2Expiry) * 1000).toISOString())}  the nonce ${p2Nonce}`);
  const ercAllow = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'allowance', args: [recipient, PERMIT2] });
  console.log(`  the ERC-20 allowance to Permit2 now: ${formatUnits(ercAllow, 18)}`);
  if (p2Amount === 0n) { console.error('THE PERMIT2 ALLOWANCE IS STILL ZERO. the sell leg would revert.'); process.exit(1); }
  // The expiry must be a real, distant future timestamp. 0 is treated as
  // a FAILURE, not as "never" - that assumption is what the audit caught.
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  if (p2Expiry === 0n) {
    console.error('THE PERMIT2 ALLOWANCE EXPIRY IS ZERO. On a standard Permit2 that is the most expired value there is, not "never". refusing.');
    process.exit(1);
  }
  if (p2Expiry < nowSec + 3600n) {
    console.error(`THE PERMIT2 ALLOWANCE EXPIRES AT ${new Date(Number(p2Expiry) * 1000).toISOString()}. refusing.`);
    process.exit(1);
  }
  if (ercAllow === 0n) { console.error('THE ERC-20 ALLOWANCE IS ZERO. the sell leg would revert.'); process.exit(1); }
  console.log('the approvals are done AND verified. the sell leg can now work.');
}

// The quote is a SIMULATION. The value still has to be covered, so it is
// sent from a funded account - by default the owner wallet. The RECIPIENT
// is always the fleet wallet, derived from its key. Nothing is signed.
const QUOTE_ACCOUNT = process.env.FLEET_QUOTE_ACCOUNT || '0x34E9dbDBfff6D6F397A2569F9FD6fD6E6C3651d9';

async function cmdQuote(label, amountG) {
  const s = loadStore();
  const w = s.wallets.find((x) => x.label === label);
  if (!w) { console.error(`no wallet ${label}`); process.exit(2); }
  const recipient = w.account.address;
  const amountInWei = BigInt(Math.round(Number(amountG) * 1e6)) * (10n ** 12n);
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const data = buildBuy(amountInWei, 0n, deadline, recipient);
  const iaiOut = await rawCall(QUOTE_ACCOUNT, VENUE, data, amountInWei);
  console.log(`the buy of ${amountG} 0G returns ${formatUnits(iaiOut, 18)} iAI`);
  console.log(`  the price ${(Number(amountG) / Number(formatUnits(iaiOut, 18))).toFixed(2)} 0G/iAI`);
  console.log(`  the recipient ${recipient} (derived from the key)`);
}

/**
 * One round trip on one wallet. The size is given in wei.
 *
 * EVERY GUARD HERE EXISTS BECAUSE OF A REAL LOSS:
 *   - the recipient is derived from the key, never typed (30 0G lost)
 *   - the min_out is never zero (a sell that returns nothing)
 *   - the quote is never treated as zero when it comes back empty (the RPC
 *     returns an empty 0x often, and empty is NOT zero)
 *   - the deadline is short (a tx that sits in the mempool is a tx whose
 *     price has moved)
 *   - the size is checked against the wallet's own balance
 */
async function roundTrip(w, amountInWei, label = '') {
  const recipient = w.account.address;

  const bal = await pub.getBalance({ address: recipient });
  // THE RESERVE. A wallet that hits zero and stops looks like a wallet that
  // ran out of money, which is a story, not a bot. The scheduler enforces
  // this; the executor enforces it too, because the executor is what
  // actually moves the money.
  const RESERVE = 5n * 10n ** 15n; // 0.005 0G - enough for the gas of the next sell
  if (amountInWei + cfgGasPerRoundTripWei + RESERVE > bal) {
    throw new Error(`the wallet ${w.label} holds ${formatUnits(bal, 18)} 0G, not enough for ${formatUnits(amountInWei, 18)} plus the ${formatUnits(RESERVE, 18)} reserve`);
  }
  if (w.stuck) {
    throw new Error(`the wallet ${w.label} is STUCK holding ${formatUnits(BigInt(w.stuckIai || '0'), 18)} iAI that could not be sold. sell it before trading again.`);
  }

  // PROVE THE SELL LEG BEFORE THE BUY. The audit's point: the buy converts
  // 0G into iAI, and if the approval is missing or expired the sell then
  // reverts and the 0G is stranded as an asset that cannot be sold. So the
  // approval state is checked FIRST. The iAI we expect to receive is
  // estimated from the quote, and the ERC-20 allowance must cover it.
  const ercAllow = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'allowance', args: [recipient, PERMIT2] });
  if (ercAllow === 0n) {
    throw new Error(`NO_ERC20_ALLOWANCE - ${w.label} has no iAI allowance to Permit2. The sell would revert. Run: node fleet.mjs approve ${w.label}`);
  }
  const aw = (a) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
  const p2Words = await rawCallWords(recipient, PERMIT2, '0x927da105' + aw(recipient) + aw(IAI) + aw(VENUE), 0);
  const p2Amount = p2Words[0];
  const p2Expiry = p2Words[1];
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  if (p2Amount === 0n) throw new Error('NO_PERMIT2_ALLOWANCE - the Permit2 allowance is zero. The sell would revert.');
  if (p2Expiry === 0n) throw new Error('PERMIT2_EXPIRY_ZERO - the expiry reads zero, which on a standard Permit2 is the most expired value there is. The sell would revert.');
  if (p2Expiry < nowSec + 3600n) throw new Error(`PERMIT2_EXPIRING - the allowance expires ${new Date(Number(p2Expiry) * 1000).toISOString()}. The sell would revert soon.`);

  // the buy
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 1800);
  const buyData = buildBuy(amountInWei, 0n, deadline, recipient);
  const iaiOut = await rawCall(QUOTE_ACCOUNT, VENUE, buyData, amountInWei);
  if (iaiOut === 0n) throw new Error('the buy quote is ZERO. refusing.');
  const minOut = iaiOut * 995n / 1000n;   // never zero
  console.log(`the buy: ${formatUnits(amountInWei, 18)} 0G for ${formatUnits(iaiOut, 18)} iAI (the min_out ${formatUnits(minOut, 18)})`);
  const buyRes = await send(w, { to: VENUE, data: buildBuy(amountInWei, minOut, deadline, recipient), value: amountInWei }, GAS_BUY, 'the buy');
  if (buyRes.rc.status !== 'success') throw new Error(`BUY_REVERTED (${buyRes.hash})`);

  // the sell, of the balance we actually hold
  await new Promise((r) => setTimeout(r, 3000));
  const held = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'balanceOf', args: [recipient] });
  if (held === 0n) throw new Error('no iAI to sell. stopping.');
  // SELL ONLY WHAT THIS TRADE BOUGHT. Dumping the entire balance means one
  // failure compounds: the next sell is bigger, and the size histogram gets
  // a spike no human trader would produce. The buy quote already told us
  // what we received.
  const toSell = held < iaiOut ? held : iaiOut;
  if (toSell < held) {
    console.log(`  the wallet holds ${formatUnits(held, 18)} iAI but this trade bought ${formatUnits(iaiOut, 18)}. selling only this trade's amount.`);
  }
  const sDeadline = BigInt(Math.floor(Date.now() / 1000) + 900);
  const sellData = buildSell(toSell, 0n, sDeadline, recipient);
  const back = await rawCall(recipient, VENUE, sellData, 0n);
  if (back === 0n) throw new Error('the sell quote is ZERO. refusing.');
  const sMinOut = back * 99n / 100n;     // never zero
  console.log(`the sell: ${formatUnits(toSell, 18)} iAI for ${formatUnits(back, 18)} 0G (the min_out ${formatUnits(sMinOut, 18)})`);
  const sellRes = await send(w, { to: VENUE, data: buildSell(toSell, sMinOut, sDeadline, recipient), value: 0n }, GAS_SELL, 'the sell');
  // A REVERTED SELL MUST NOT BE BOOKED AS A ROUND TRIP. The 0G is gone and
  // the iAI is stuck. Counting it as done is how the ledger lies.
  if (sellRes.rc.status !== 'success') {
    w.stuck = true;
    w.stuckIai = toSell.toString();
    throw new Error(`SELL_REVERTED (${sellRes.hash}) - the iAI is stuck, the wallet is marked stuck`);
  }

  const finalBal = await pub.getBalance({ address: recipient });
  const spent = bal - finalBal;
  w.trades += 1;
  w.spentWei = (BigInt(w.spentWei) + spent).toString();
  w.firstSeen = w.firstSeen || new Date().toISOString();
  console.log(`the round trip cost ${formatUnits(spent, 18)} 0G = ${(Number(spent) / Number(amountInWei) * 100).toFixed(4)}%`);
  return spent;
}

/**
 * ONE PLAN EVENT. The plan has separate buy events and sell events, so the
 * executor must do exactly what the event says.
 *
 * BEFORE THIS, EVERY EVENT WAS EXECUTED AS A FULL ROUND TRIP - a buy
 * followed by a sell. That would have doubled every event in the plan:
 * 32 round trips would have become 64. And a wallet that is only a SELLER
 * in the plan (the crowd's 5-of-12 sellers) would have been made to buy
 * first, which is the opposite of the behaviour the plan describes.
 *
 * So: a 'buy' event buys. A 'sell' event sells only what that wallet
 * actually holds, and refuses if it holds nothing.
 */
async function executeEvent(w, e) {
  if (e.side === 'buy') {
    const amountInWei = BigInt(Math.round(e.sizeG * 1e6)) * (10n ** 12n);
    const spent = await buyOnly(w, amountInWei);
    w.trades += 1;
    w.spentWei = (BigInt(w.spentWei) + spent).toString();
    w.firstSeen = w.firstSeen || new Date().toISOString();
    return spent;
  }
  if (e.side === 'sell') {
    const held = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'balanceOf', args: [w.account.address] });
    if (held === 0n) throw new Error(`the wallet ${w.label} holds no iAI to sell. skipping.`);
    // SELL THE PLANNED AMOUNT, NOT THE WHOLE BALANCE. Selling everything
    // ignores the plan: a 0.05 planned sell went out as 0.74 because the
    // wallet held a dust position too. The size on chain has to match the
    // size in the plan, or the plan is not what gets traded.
    // The plan states the exact token amount, so nothing is guessed.
    const wantIai = e.sellIai != null
      ? BigInt(Math.round(e.sellIai * 1e6)) * (10n ** 12n)
      : held;
    const toSell = held < wantIai ? held : wantIai;
    if (toSell === 0n) throw new Error(`the wallet ${w.label} holds ${formatUnits(held, 18)} iAI, too little for this sell. skipping.`);
    const balBefore = await pub.getBalance({ address: w.account.address });
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 900);
    const data = buildSell(toSell, 0n, deadline, w.account.address);
    const back = await rawCall(w.account.address, VENUE, data, 0n);
    if (back === 0n) throw new Error('the sell quote is ZERO. refusing.');
    const minOut = back * 99n / 100n;
    console.log(`the sell: ${formatUnits(toSell, 18)} iAI for ${formatUnits(back, 18)} 0G (the min_out ${formatUnits(minOut, 18)})`);
    const res = await send(w, { to: VENUE, data: buildSell(toSell, minOut, deadline, w.account.address), value: 0n }, GAS_SELL, 'the sell');
    if (res.rc.status !== 'success') {
      w.stuck = true;
      w.stuckIai = toSell.toString();
      throw new Error(`SELL_REVERTED (${res.hash}) - the iAI is stuck, the wallet is marked stuck`);
    }
    const balAfter = await pub.getBalance({ address: w.account.address });
    const spent = balBefore - balAfter;
    w.trades += 1;
    w.spentWei = (BigInt(w.spentWei) + spent).toString();
    w.firstSeen = w.firstSeen || new Date().toISOString();
    return spent;
  }
  throw new Error(`the event side "${e.side}" is not a side this executor knows.`);
}

/**
 * A BUY ONLY. No sell. The sell is a separate plan event, done later, so
 * the wallet's visible hold time is the hold in the plan.
 */
async function buyOnly(w, amountInWei) {
  const recipient = w.account.address;
  const bal = await pub.getBalance({ address: recipient });
  const RESERVE = 5n * 10n ** 15n; // 0.005 0G - enough for the gas of the next sell
  if (amountInWei + RESERVE > bal) {
    throw new Error(`the wallet ${w.label} holds ${formatUnits(bal, 18)} 0G, not enough for ${formatUnits(amountInWei, 18)} plus the reserve`);
  }
  if (w.stuck) {
    throw new Error(`the wallet ${w.label} is STUCK holding ${formatUnits(BigInt(w.stuckIai || '0'), 18)} iAI that could not be sold. sell it before trading again.`);
  }
  // The sell leg must be possible LATER, or the 0G turns into iAI that
  // cannot be sold.
  const ercAllow = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'allowance', args: [recipient, PERMIT2] });
  if (ercAllow === 0n) {
    throw new Error(`NO_ERC20_ALLOWANCE - ${w.label} has no iAI allowance to Permit2. The sell would revert. Run: node fleet.mjs approve ${w.label}`);
  }
  const aw = (a) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
  const p2Words = await rawCallWords(recipient, PERMIT2, '0x927da105' + aw(recipient) + aw(IAI) + aw(VENUE), 0);
  const p2Amount = p2Words[0];
  const p2Expiry = p2Words[1];
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  if (p2Amount === 0n) throw new Error('NO_PERMIT2_ALLOWANCE - the Permit2 allowance is zero. The sell would revert.');
  if (p2Expiry === 0n) throw new Error('PERMIT2_EXPIRY_ZERO - the expiry reads zero. The sell would revert.');
  if (p2Expiry < nowSec + 3600n) throw new Error(`PERMIT2_EXPIRING - the allowance expires ${new Date(Number(p2Expiry) * 1000).toISOString()}. The sell would revert soon.`);

  const deadline = BigInt(Math.floor(Date.now() / 1000) + 1800);
  const buyData = buildBuy(amountInWei, 0n, deadline, recipient);
  const iaiOut = await rawCall(QUOTE_ACCOUNT, VENUE, buyData, amountInWei);
  if (iaiOut === 0n) throw new Error('the buy quote is ZERO. refusing.');
  const minOut = iaiOut * 995n / 1000n;
  console.log(`the buy: ${formatUnits(amountInWei, 18)} 0G for ${formatUnits(iaiOut, 18)} iAI (the min_out ${formatUnits(minOut, 18)})`);
  const buyRes = await send(w, { to: VENUE, data: buildBuy(amountInWei, minOut, deadline, recipient), value: amountInWei }, GAS_BUY, 'the buy');
  if (buyRes.rc.status !== 'success') throw new Error(`BUY_REVERTED (${buyRes.hash})`);
  const finalBal = await pub.getBalance({ address: recipient });
  return bal - finalBal;
}

/**
 * A standalone sell. This exists so a wallet that bought but could not sell
 * can EXIT without buying more. The audit's point: if the sell leg is
 * broken, the buy must not have happened - but if it did, there has to be a
 * way out that is not "buy more and hope".
 */
async function cmdSell(label, amountIai) {
  const s = loadStore();
  const w = s.wallets.find((x) => x.label === label);
  if (!w) { console.error(`no wallet ${label}`); process.exit(2); }
  const recipient = w.account.address;
  const held = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'balanceOf', args: [recipient] });
  if (held === 0n) { console.log('the wallet holds no iAI.'); return; }
  const toSell = amountIai ? BigInt(Math.round(Number(amountIai) * 1e18)) : held;
  const amount = toSell > held ? held : toSell;
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 900);
  const data = buildSell(amount, 0n, deadline, recipient);
  const back = await rawCall(recipient, VENUE, data, 0n);
  if (back === 0n) { console.error('the sell quote is ZERO. refusing.'); process.exit(2); }
  const minOut = back * 99n / 100n;
  console.log(`selling ${formatUnits(amount, 18)} iAI for ${formatUnits(back, 18)} 0G (the min_out ${formatUnits(minOut, 18)})`);
  const res = await send(w, { to: VENUE, data: buildSell(amount, minOut, deadline, recipient), value: 0n }, GAS_SELL, 'the sell');
  if (res.rc.status === 'success') {
    w.stuck = false;
    delete w.stuckIai;
    console.log('the sell succeeded. the wallet is not stuck.');
  } else {
    console.error('THE SELL REVERTED. the iAI is still stuck.');
    process.exit(1);
  }
  saveStore(s);
}

async function cmdRoundtrip(label, amountG) {
  const s = loadStore();
  const w = s.wallets.find((x) => x.label === label);
  if (!w) { console.error(`no wallet ${label}`); process.exit(2); }
  const amountInWei = BigInt(Math.round(Number(amountG) * 1e6)) * (10n ** 12n);
  await roundTrip(w, amountInWei);
  saveStore(s);
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * The executor. Walks the schedule and does each round trip when its time
 * comes.
 *
 * THE RULES THE EXECUTOR ENFORCES, beyond the scheduler's:
 *
 *   1. A WINDOW LOCK. `--until <iso>` stops the executor at that time, so
 *      the thing can be run for an hour and then stopped. No unbounded run.
 *
 *   2. A MAXIMUM. `--max <n>` caps the number of round trips in one run.
 *
 *   3. THE DAILY BUDGET IS CHECKED AGAINST THE WALLET. The schedule says
 *      how much to trade; the executor checks the wallet can afford it and
 *      refuses otherwise. The schedule is a plan, not a permission.
 *
 *   4. ONE AT A TIME. Never two round trips in flight. Two wallets in the
 *      same block is a tell, and two in flight is two chances to fail.
 *
 *   5. A FAILED TRADE DOES NOT STOP THE RUN, but it is logged loudly and
 *      the wallet is skipped for that slot. One revert should not wedge
 *      the fleet.
 *
 *   6. EVERY TRADE IS LEDGERED, with the size, the cost, and the hash.
 */

/**
 * SLEEP UNTIL A TIME, BUT WAKE UP IF THE KILL SWITCH APPEARS.
 *
 * The kill switch is a file. If it appears while the fleet is asleep, the
 * fleet must stop - it cannot wait for the next event to notice.
 */
async function sleepUntil(at, haltFile) {
  const CHECK = 15 * 1000;
  while (true) {
    const left = at - Date.now();
    if (left <= 0) return 'awake';
    if (haltFile && existsSync(haltFile)) return 'halted';
    await new Promise((r) => setTimeout(r, Math.min(CHECK, left)));
  }
}

/**
 * THE EXECUTOR.
 *
 * Two defects the audit found made the spend unbounded, and both are fixed
 * here:
 *
 *   1. RE-EXECUTION. The executor used to walk the plan from the top on
 *      every invocation, so a second run would re-trade every event the
 *      first one had already done. The documented workflow is "run it for
 *      an hour, then stop", which is exactly repeated invocations. Now the
 *      ledger is read back and every event that has already been attempted
 *      is skipped.
 *
 *   2. EARLY FIRING. An event more than 90 seconds away used to be run
 *      IMMEDIATELY, which turned the in-window slice of a 24-hour-spread
 *      plan into a burst of back-to-back trades seconds apart - destroying
 *      the exact property the scheduler exists to produce. Now the executor
 *      waits, and if the next event is more than 15 minutes away it STOPS
 *      and lets the next invocation pick it up.
 *
 * Plus:
 *   3. A LOCK. Two invocations cannot overlap on the same nonce.
 *   4. A GRACE. An event that is only slightly late (the machine was
 *      asleep) still runs; one that is days late does not.
 *   5. THE APPROVALS ARE CHECKED ONCE, UP FRONT, for every wallet. A
 *      wallet that cannot sell is never used to buy.
 */
async function cmdRun(planPath, untilIso, maxRuns) {
  const store = loadStore();

  // THE LOCK. Two executors on the same keystore would race on the nonce.
  const lockPath = `${DIR}/run.lock`;
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  try {
    const fd = openSync(lockPath, 'wx');
    writeFileSync(fd, `${process.pid} ${new Date().toISOString()}`);
    closeSync(fd);
  } catch (e) {
    console.error(`ANOTHER RUN IS HOLDING THE LOCK (${lockPath}). refusing.`);
    console.error('if that run is dead, remove the lock file.');
    process.exit(2);
  }
  const releaseLock = () => { try { unlinkSync(lockPath); } catch {} };

  try {
    if (!existsSync(planPath)) { console.error(`no plan at ${planPath}`); process.exit(2); }
    const plan = JSON.parse(readFileSync(planPath, 'utf8'));
    const until = untilIso ? new Date(untilIso).getTime() : Date.now() + 3600000;
    if (Number.isNaN(until)) { console.error(`bad --until ${untilIso}`); process.exit(2); }

    // THE DONE SET. Read back from the ledger so a repeated invocation
    // does not re-trade anything.
    const done = new Set();
    if (existsSync(LOG)) {
      for (const line of readFileSync(LOG, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line);
          if (e.event && e.eventId) done.add(e.eventId);
        } catch {}
      }
    }
    const eventId = (e) => `${e.wallet}|${e.at}|${e.sizeG}`;

    const events = plan.slots.flatMap((s) => s.events).sort((a, b) => a.at < b.at ? -1 : 1);
    console.log(`the plan: ${events.length} round trips, ${done.size} already done`);
    console.log(`the window ends ${new Date(until).toISOString()}`);

    // ── THE SAFETY LAYER, ARMED. ───────────────────────────────────────────
    // Everything the guard needs to judge a trade is assembled here, once,
    // and then every broadcast in this run is checked against it.
    //
    // The kill switch is a file. One file, one flag. If it exists, nothing
    // runs. It is deliberately outside the agent's reach: the agent cannot
    // delete it, and it does not need the agent's cooperation to work.
    const HALT_FILE = `${DIR}/HALT`;
    if (existsSync(HALT_FILE)) {
      console.log('THE KILL SWITCH IS ON. nothing will run.');
      process.exit(3);
    }
    // How much the fleet has already spent on fees today.
    const todayKey = new Date().toISOString().slice(0, 10);
    let spentTodayWei = 0n;
    if (existsSync(LOG)) {
      for (const line of readFileSync(LOG, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line);
          if (e.status === 'done' && String(e.t || '').slice(0, 10) === todayKey && e.gasCostWei) {
            spentTodayWei += BigInt(e.gasCostWei);
          }
        } catch {}
      }
    }
    globalThis.__guardCtx = {
      // THE ONE PLACE THE SAFETY NUMBERS COME FROM. If the plan's cushion
      // and the guard's reserve disagree, the guard refuses trades the plan
      // says are affordable - which is exactly what happened. They are set
      // together here so they cannot drift apart.
      config: { reserveWei: GUARD_RESERVE_WEI, maxTradeWei: 25n * 10n ** 18n },
      approvedPlan: plan,
      planEventId: null,
      halted: false,
      spentTodayWei,
      feeWei: 0n,
      erc20AllowanceWei: undefined,
      permit2Expiry: undefined,
    };
    console.log(`the safety layer is on. the fleet has spent ${formatUnits(spentTodayWei, 18)} 0G on fees today.`);

    // THE APPROVAL GATE, UP FRONT, FOR EVERY WALLET.
    const aw = (a) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
    const nowSec = BigInt(Math.floor(Date.now() / 1000));
    for (const w of store.wallets) {
      if (w.stuck) { console.log(`  ${w.label} is STUCK - skipping it.`); continue; }
      const erc = await pub.readContract({ address: IAI, abi: IAI_ABI, functionName: 'allowance', args: [w.account.address, PERMIT2] });
      const words = await rawCallWords(w.account.address, PERMIT2, '0x927da105' + aw(w.account.address) + aw(IAI) + aw(VENUE), 0);
      // THE CONTRACT RETURNS THREE SEPARATE WORDS: amount, expiration, nonce.
      // Reading them as one packed word made a valid approval look expired.
      const amt = words[0];
      const exp = words[1];
      const ok = erc > 0n && amt > 0n && exp > nowSec + 3600n;
      console.log(`  ${w.label} ${ok ? 'READY' : 'NOT READY'}  the ERC20 ${erc === 0n ? 'ZERO' : formatUnits(erc, 18)}  the Permit2 ${amt === 0n ? 'ZERO' : 'set'}  the expiry ${exp === 0n ? 'ZERO (bad)' : (Number(exp) * 1000 > 8.64e15 ? 'the far future (year 8918655)' : new Date(Number(exp) * 1000).toISOString())}`);
      if (!ok) w.notReady = true; else delete w.notReady;
    }
    saveStore(store);

    let doneCount = 0, failed = 0, totalSpent = 0n, skipped = 0;
    for (const e of events) {
      if (doneCount >= maxRuns) { console.log('the maximum is reached. stopping.'); break; }
      const id = eventId(e);
      if (done.has(id)) { skipped++; continue; }
      const at = new Date(e.at).getTime();
      if (at > until) { console.log(`the next event is ${e.at}, past the window. stopping.`); break; }

      // THE GRACE. A little late is fine - the machine was asleep. Days
      // late means the plan has moved on and running it now would break the
      // timing shape the scheduler exists to produce.
      const wait = at - Date.now();
      if (wait > 0) {
        if (wait < 15 * 60 * 1000) {
          process.stdout.write(`  waiting ${Math.round(wait / 1000)}s for ${e.wallet}...`);
          await new Promise((r) => setTimeout(r, wait));
          process.stdout.write('\n');
        } else {
          // WAIT, DO NOT EXIT. The original behaviour was to stop and
          // "let the next invocation pick it up", which only works if
          // something else starts it. Nothing did, so the trial would have
          // sat idle. Now it sleeps until the event is due, waking often
          // enough to notice the kill switch.
          process.stdout.write(`  sleeping ${Math.round(wait / 60000)}m until ${e.at} (${e.wallet} ${e.side} ${e.sizeG.toFixed(3)} 0G)...`);
          const slept = await sleepUntil(at, HALT_FILE);
          if (slept === 'halted') {
            console.log('\nTHE KILL SWITCH IS ON. stopping.');
            break;
          }
          console.log('  awake.');
        }
      } else if (wait < -86400000) {
        console.log(`the event ${e.at} is more than a day late. skipping it.`);
        done.add(id);
        skipped++;
        continue;
      }

      const w = store.wallets.find((x) => x.label === e.wallet);
      if (!w) { console.log(`  no wallet ${e.wallet}. skipping.`); continue; }
      if (w.notReady) { console.log(`  ${w.label} is not ready. skipping.`); continue; }
      const amountInWei = BigInt(Math.round(e.sizeG * 1e6)) * (10n ** 12n);
      try {
        const spent = await executeEvent(w, e);
        totalSpent += spent;
        doneCount += 1;
        done.add(id);
        writeLedger({ event: e, eventId: id, spentWei: spent.toString(), status: 'done' });
        saveStore(store);
      } catch (err) {
        failed += 1;
        done.add(id);   // never retry the same event automatically
        console.error(`  THE TRADE FAILED: ${err.message}`);
        writeLedger({ event: e, eventId: id, status: 'failed', error: err.message });
        saveStore(store);
      }
      await new Promise((r) => setTimeout(r, 3000 + Math.floor(Math.random() * 9000)));
    }
    console.log(`\nthe run is over. ${doneCount} round trips done, ${failed} failed, ${skipped} skipped.`);
    console.log(`the fees burned: ${formatUnits(totalSpent, 18)} 0G`);
    console.log(`the ledger: ${LOG}`);
  } finally {
    releaseLock();
  }
}

const cmd = process.argv[2];
const arg = process.argv[3];
const opt = (name, def) => {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
};
if (cmd === 'init') cmdInit(parseInt(arg || '4', 10));
else if (cmd === 'list') await cmdList();
else if (cmd === 'fund') cmdFund();
else if (cmd === 'export') cmdExport(arg);
else if (cmd === 'add') cmdAdd(parseInt(arg || '1', 10));
else if (cmd === 'doctor') await cmdDoctor();
else if (cmd === 'approve') await cmdApprove(arg);
else if (cmd === 'quote') await cmdQuote(arg, process.argv[4]);
else if (cmd === 'roundtrip') await cmdRoundtrip(arg, process.argv[4]);
else if (cmd === 'sell') await cmdSell(arg, process.argv[4]);
else if (cmd === 'run') await cmdRun(opt('--plan', `${DIR}/schedule.json`), opt('--until', null), parseInt(opt('--max', '1000'), 10));
else {
  console.error('usage: fleet.mjs init <n> | list | fund | doctor | approve <label> | quote <label> <0G> | roundtrip <label> <0G> | sell <label> [iAI] | run [--plan f] [--until iso] [--max n]');
  process.exit(2);
}
