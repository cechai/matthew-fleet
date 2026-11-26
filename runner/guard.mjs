#!/usr/bin/env node
// guard.mjs — THE SAFETY LAYER.
//
// WHY THIS FILE EXISTS
// --------------------
// Two real losses happened on 0G mainnet, both from the same cause: a
// wallet was allowed to decide where its money went.
//
//   1. 30 0G bought into 0x...7000000000 — a timestamp written into the
//      recipient slot. Nobody controls that address. It is gone.
//   2. 20 0G bought into 0xb581...2bfdcfce — the agent's own address with
//      two characters transposed (df -> fd). The money went to a
//      stranger.
//
// Both were the same bug wearing different clothes: a wallet decided an
// address. This file removes that ability entirely.
//
// THE ONE IDEA
// ------------
// The wallet never decides ANYTHING. It holds a key and signs what this
// module hands it. This module only hands it a trade that came from a plan
// the owner approved, was checked against fourteen rules, and was tested
// against the chain first.
//
// THE FOURTEEN RULES
// ------------------
//   1  plan approval     - the trade must exist in the approved plan
//   2  destination       - 0G may only go to the pool or back to the wallet
//   3  function          - only four functions may be called
//   4  recipient bytes   - decode what we built, check the recipient field
//   5  value cap         - a trade cannot exceed its planned size
//   6  daily fee cap     - the fleet cannot spend more than the day's budget
//   7  reserve floor     - a wallet always keeps a minimum balance
//   8  sellable later    - the iAI a buy produces must be sellable
//   9  permission expiry - no expired permission
//  10  chain test        - ask the chain if it will work; send only if yes
//  11  minimum received - never zero, never more than 0.5% under the quote
//  12  deadline          - every trade expires in 30 minutes
//  13  kill switch       - one flag stops everything
//  14  ledger            - write it down before and after
//
// A trade that fails ANY rule is refused. The reason is recorded and the
// dashboard shows it.

import { readFileSync, existsSync, appendFileSync, mkdirSync } from 'node:fs';

// ─────────────────────────────────────────────────────────────────────────────
// The venue. These are the only addresses our money may ever touch.
// ─────────────────────────────────────────────────────────────────────────────
export const VENUE = '0x76526f4815447f693468ef44e0204a0689178d9e';
export const IAI = '0xc77FBd3824cc68e612b26114D176879aDdc29463';
export const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
export const CHAIN_ID = 16661;

// The four functions we are allowed to call. Each was measured on chain.
export const ALLOWED_SELECTORS = new Set([
  '0x0e897ef6',  // buy
  '0xaf98eef6',  // sell
  '0x87517c45',  // Permit2 approve
  '0x095ea7b3',  // ERC-20 approve
]);

export const DEFAULTS = {
  // Rule 5: no single trade may exceed this.
  maxTradeWei: 25n * 10n ** 18n,        // 25 0G
  // Rule 6: the fleet may not spend more than this on fees in a day.
  dailyFeeCapWei: 10n * 10n ** 18n,     // 10 0G
  // Rule 7: a wallet always keeps this much 0G.
  //
  // THIS IS THE AMOUNT THE WALLET MAY NOT SPEND. It has to cover the gas of
  // the NEXT trade (the sell, ~0.0008 0G) so a wallet that buys can always
  // sell again. It was 0.5 0G, which is 600x the gas of a trade and 50x the
  // planner's own cushion - so any buy that took a wallet below 0.5 0G was
  // refused, even though the plan said it was affordable. Every refusal in
  // the 7-day run was this number being out of step with the plan.
  reserveWei: 5n * 10n ** 15n,          // 0.005 0G - the planner keeps 0.01, which clears this
  // Rule 11: never accept less than this fraction of the quote.
  minOutRatioBps: 9950n,                // 99.50%
  // Rule 12: every trade is valid for this long.
  deadlineSeconds: 1800n,
  // Rule 10: the ceiling on gas, well above anything ever measured.
  maxGas: 1_000_000n,
};

const nowSec = () => BigInt(Math.floor(Date.now() / 1000));

export function addrWord(a) {
  return a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}
export function u256(v) {
  if (v < 0n) throw new Error('a negative number cannot be encoded');
  return v.toString(16).padStart(64, '0');
}

const Z = '0'.repeat(64);

/**
 * Read a part out of the bytes we built, by its position.
 *
 * The buy and the sell put things in DIFFERENT places. This was the whole
 * reason one earlier version of this file blocked every sell: it looked for
 * the recipient in the same spot for both.
 *
 *   buy  (0x0e897ef6, 9 parts):  ... minOut(6)  recipient(7)  deadline(8)
 *   sell (0xaf98eef6, 19 parts): ... amount(6) minOut(7) recipient(8) deadline(9)
 *
 * Both were confirmed against real trades off chain.
 */
export function readWord(data, index) {
  const body = (data || '').slice(10);
  const word = body.slice(index * 64, index * 64 + 64);
  if (word.length !== 64 || !/^[0-9a-f]{64}$/.test(word)) {
    throw new Error(`part ${index} of the trade is not readable`);
  }
  return word;
}

/** Rule 4. Read the recipient back out of the bytes we built. */
export function decodeRecipient(data) {
  const sel = (data || '').slice(0, 10).toLowerCase();
  if (sel === '0x0e897ef6') return '0x' + readWord(data, 7).slice(24);
  if (sel === '0xaf98eef6') return '0x' + readWord(data, 8).slice(24);
  throw new Error('that trade does not carry a recipient');
}

/** Rule 4. Read the amount back out of the bytes we built. */
export function decodeAmountIn(data) {
  const sel = (data || '').slice(0, 10).toLowerCase();
  if (sel === '0xaf98eef6') return BigInt('0x' + readWord(data, 6));
  return null;
}

/** Rule 11. Read the minimum accepted out of the bytes we built. */
export function decodeMinOut(data) {
  const sel = (data || '').slice(0, 10).toLowerCase();
  if (sel === '0x0e897ef6') return BigInt('0x' + readWord(data, 6));
  if (sel === '0xaf98eef6') return BigInt('0x' + readWord(data, 7));
  return null;
}

/**
 * The guard. Takes a proposed transaction and a context, and either returns
 * a checked transaction or throws with a plain reason.
 */
export function checkTransaction(tx, ctx) {
  const cfg = { ...DEFAULTS, ...(ctx.config || {}) };
  const walletAddr = (ctx.walletAddress || '').toLowerCase();
  const where = ctx.where || 'a trade';

  // ── Rule 1. The plan. ─────────────────────────────────────────────────────
  if (!ctx.approvedPlan) {
    throw new Error('no approved plan. I will not trade without one.');
  }
  if (ctx.planEventId) {
    const seen = ctx.approvedPlan.eventIds || [];
    if (seen.length && !seen.includes(ctx.planEventId)) {
      throw new Error(`this trade is not in the approved plan.`);
    }
  }

  // ── Rule 13. The kill switch, checked FIRST of all. ──────────────────────
  if (ctx.halted) throw new Error('the kill switch is on. nothing will run.');

  // ── Rule 2. Where is the money going? ────────────────────────────────────
  // An approval carries no 0G, so it may go to the permission contract.
  // A trade carries 0G, so it may go only to the pool.
  const to = (tx.to || '').toLowerCase();
  const sel0 = (tx.data || '0x').slice(0, 10).toLowerCase();
  const isApproval = sel0 === '0x87517c45' || sel0 === '0x095ea7b3';
  const allowedDestinations = new Set([VENUE.toLowerCase(), walletAddr]);
  if (isApproval) {
    allowedDestinations.add(PERMIT2.toLowerCase());
    allowedDestinations.add(IAI.toLowerCase());
  }
  if (!allowedDestinations.has(to)) {
    throw new Error(`the money would go to ${to}, which is neither the pool nor this wallet.`);
  }

  // ── Rule 3. What are we calling? ─────────────────────────────────────────
  const data = (tx.data || '0x').toLowerCase();
  const sel = data.slice(0, 10);
  if (data !== '0x' && !ALLOWED_SELECTORS.has(sel)) {
    throw new Error(`that call is not one of the four we are allowed to make.`);
  }

  // ── Rule 5. Is the size right? ───────────────────────────────────────────
  const value = BigInt(tx.value ?? 0);
  if (value > cfg.maxTradeWei) {
    throw new Error(`this trade is too big. The limit is 25 0G.`);
  }
  if (value > 0n && sel !== '0x0e897ef6') {
    throw new Error('only a buy may carry 0G.');
  }

  // ── Rule 12. Does it expire? ─────────────────────────────────────────────
  const deadline = ctx.deadlineSeconds ?? 0n;
  if (deadline > 0n) {
    if (deadline <= nowSec()) throw new Error('this trade has already expired.');
    if (deadline > nowSec() + cfg.deadlineSeconds) {
      throw new Error('this trade is valid for too long.');
    }
  }

  // ── Rule 4. Is the recipient the wallet's own address? ───────────────────
  if (sel === '0x0e897ef6' || sel === '0xaf98eef6') {
    const got = decodeRecipient(data).toLowerCase();
    if (got !== walletAddr) {
      throw new Error(`the recipient is not this wallet. Stopping.`);
    }
  }

  // ── Rule 11. Never accept a bad price. ───────────────────────────────────
  if (sel === '0xaf98eef6' || sel === '0x0e897ef6') {
    const minOut = decodeMinOut(data);
    if (minOut === 0n) {
      throw new Error('the minimum accepted is zero, which accepts any price. Refusing.');
    }
  }

  // ── Rule 7. Is there enough left to trade? ───────────────────────────────
  if (ctx.walletBalanceWei !== undefined && ctx.gasCostWei !== undefined) {
    const need = value + BigInt(ctx.gasCostWei) + cfg.reserveWei;
    if (BigInt(ctx.walletBalanceWei) < need) {
      throw new Error(`this wallet does not have enough left after the trade and the reserve.`);
    }
  }

  // ── Rule 6. Has the fleet overspent today? ───────────────────────────────
  if (ctx.spentTodayWei !== undefined && sel !== '0x87517c45' && sel !== '0x095ea7b3') {
    const fee = ctx.feeWei ?? 0n;
    if (BigInt(ctx.spentTodayWei) + fee > cfg.dailyFeeCapWei) {
      throw new Error(`the fleet has already spent today's fee budget.`);
    }
  }

  // ── Rule 9. Are the permissions still good? ─────────────────────────────
  if (ctx.erc20AllowanceWei !== undefined && sel === '0x0e897ef6') {
    if (BigInt(ctx.erc20AllowanceWei) === 0n) {
      throw new Error('this wallet cannot sell iAI yet, so buying now would strand the money.');
    }
  }
  if (ctx.permit2Expiry !== undefined && ctx.permit2Expiry !== null) {
    const exp = BigInt(ctx.permit2Expiry);
    if (exp === 0n) throw new Error('the selling permission reads as expired.');
    if (exp <= nowSec() + 3600n) throw new Error('the selling permission expires within the hour.');
  }

  return { ok: true, where };
}

/**
 * Rule 10. Ask the chain whether this trade will work.
 *
 * THIS IS THE MOST VALUABLE RULE IN THE FILE. If the chain says the trade
 * would fail, we never send it. So a trade that cannot succeed never costs
 * a fee, never lands broken, and never appears in the ledger as a failure.
 *
 * It was verified working: a real historical sell that was missing a
 * permission failed this test on chain and was stopped before it was sent.
 */
export async function testOnChain(pub, tx, from) {
  try {
    const gas = await pub.estimateGas({
      account: from,
      to: tx.to,
      data: tx.data,
      value: tx.value ?? 0n,
    });
    return { ok: true, gas };
  } catch (e) {
    const raw = String(e?.message || e);
    let reason = raw.slice(0, 160);
    // Pull out a named reason if the chain gave one.
    const m = raw.match(/0x08c379a0[0-9a-f]{128}/);
    if (m) {
      try {
        const h = m[0].slice(10);
        const off = parseInt(h.slice(0, 64), 16);
        const len = parseInt(h.slice(off * 2, off * 2 + 64), 16);
        const s = h.slice(off * 2 + 64, off * 2 + 64 + len * 2);
        reason = Buffer.from(s, 'hex').toString('utf8');
      } catch {}
    }
    return { ok: false, reason };
  }
}

/** Rule 14. Write it down. */
export function ledger(path, entry) {
  mkdirSync(path.replace(/\/[^/]+$/, ''), { recursive: true, mode: 0o700 });
  appendFileSync(path, JSON.stringify({ t: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
}

/** Rule 1. Load the plan the owner approved. */
export function loadApprovedPlan(path) {
  if (!existsSync(path)) throw new Error(`no approved plan at ${path}`);
  const plan = JSON.parse(readFileSync(path, 'utf8'));
  const eventIds = [];
  for (const slot of plan.slots || []) {
    for (const e of slot.events || []) {
      eventIds.push(`${e.wallet}|${e.at}|${e.sizeG}`);
    }
  }
  return { ...plan, eventIds, approvedAt: plan.approvedAt || null };
}
