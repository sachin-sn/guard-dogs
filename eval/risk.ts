/**
 * The exact risk of a panel.
 *
 * Question: if each dog can be wrong, how often does the gate let a bad action
 * run, and how often does it let a good one run, as the panel gets bigger or
 * gets its models from different families?
 *
 * The answer is computed, not sampled. Every way a panel of 2 to 9 dogs can
 * vote (approve, reject or stay silent, 3^n ways) is put through the real gate,
 * `evaluateAction`, with a pre-approved containment, so the majority rule, the
 * model-diversity rule and the minority alert are the gate's own and cannot
 * drift from a copy kept here. Each way of voting is then weighted by how likely
 * it is under a small failure model:
 *
 * - `silent`: a dog gives no usable vote (a timeout, a refusal, unreadable
 *   output). It counts as not agreeing.
 * - `error`: a dog whose family is not fooled still votes wrongly, on its own.
 * - `shared`: the chance that a whole model family is fooled at once (the same
 *   blind spot, the same injected notice). Every dog of that family then votes
 *   wrongly. Families are fooled independently of each other.
 *
 * "Wrongly" means approving a bad proposal, or rejecting a good one.
 *
 * The numbers describe how the rule treats a failure pattern. They do not
 * measure any real model: the three rates are inputs, not findings. What the
 * module settles exactly is the structure: how much panel size buys, how much
 * composition buys, and where the floor is.
 */

import type { ActionVote, ProposedAction } from '../src/core/types.js';
import { evaluateAction, type GateOutcome } from '../src/gate/gate.js';
import { createGatePolicy, MAX_PANEL_SIZE, type GatePolicy } from '../src/gate/policy.js';

export interface Seat {
  /** The model family, which is the unit that shares a blind spot. */
  family: string;
  /** The model id as the panel policy names it. The gate wants approvers to span two of these. */
  model: string;
}

/** Each rate is one number for every family, or a number per family (families not named get 0). Default 0. */
export type Rate = number | Readonly<Record<string, number>>;

export interface FailureModel {
  /** Chance a dog gives no usable vote. */
  silent?: Rate;
  /** Chance a dog in an unfooled family votes wrongly, on its own. */
  error?: Rate;
  /** Chance that a family is fooled, so that all its dogs vote wrongly at once. */
  shared?: Rate;
}

export interface GateOptions {
  rule?: 'majority' | 'unanimous';
  requireDistinctModels?: boolean;
  dissentAlertMin?: number;
  /** Approvals needed from outside the largest approving family. Default 0, the gate's present rule. */
  minOutsideFamily?: number;
}

/** What the gate did, over the whole of one truth's probability. The three outcomes add up to 1. */
export interface Odds {
  /** The action ran. For a bad proposal this is the harm; for a good one it is the protection. */
  execute: number;
  /** The action waits for a person. */
  awaitHuman: number;
  /** The panel rejected it. */
  deny: number;
  /** Not run, but at least `dissentAlertMin` dogs approved, so a person is told. Part of `awaitHuman` and `deny`. */
  dissent: number;
  /** Waiting because the panel did not agree. Part of `awaitHuman`. */
  split: number;
  /** Waiting because the approvals came from one model. Part of `awaitHuman`. */
  notDiverse: number;
  /** Waiting because too few approvals came from outside the largest approving family. Part of `awaitHuman`. */
  oneSided: number;
}

export interface PanelRisk {
  size: number;
  /** The proposal is wrong and should not run. */
  bad: Odds;
  /** The proposal is right and should run. */
  good: Odds;
}

/** What the gate decided for one way of voting. */
export interface Cell {
  outcome: GateOutcome;
  flagged: boolean;
  split: boolean;
  notDiverse: boolean;
  oneSided: boolean;
}

export const MIXES = ['one-model', 'one-family', 'two-families', 'three-families'] as const;
export type Mix = (typeof MIXES)[number];

const FAMILY_COUNT: Readonly<Record<Mix, number>> = { 'one-model': 1, 'one-family': 1, 'two-families': 2, 'three-families': 3 };
const FAMILY_NAMES = ['family-a', 'family-b', 'family-c'] as const;

/**
 * The seats of a panel of a given make-up.
 *
 * - `one-model`: every seat is the same model. The gate never lets this panel act alone.
 * - `one-family`: a different model on each seat, all of one family, as in a panel of one vendor's
 *   large and small models. The gate counts them as different; their blind spots are shared.
 * - `two-families`, `three-families`: one model per family, seats handed out in turn, which is the
 *   shape `planPanel` makes. With fewer seats than families the panel simply has fewer families.
 */
export function seatsFor(mix: Mix, size: number): Seat[] {
  if (!Number.isInteger(size) || size < 2 || size > MAX_PANEL_SIZE) throw new RangeError(`a panel has 2 to ${MAX_PANEL_SIZE} dogs`);
  const families = FAMILY_COUNT[mix];
  return Array.from({ length: size }, (_, seat) => {
    if (mix === 'one-model') return { family: FAMILY_NAMES[0], model: 'model-a' };
    if (mix === 'one-family') return { family: FAMILY_NAMES[0], model: `model-${seat + 1}` };
    const family = FAMILY_NAMES[seat % families] as string;
    return { family, model: `model-${family.slice(-1)}` };
  });
}

// The vote digits: 0 approve, 1 reject, 2 abstain. The status digits: 0 right, 1 wrong, 2 silent.
const VOTE_OF: Readonly<Record<'bad' | 'good', readonly [number, number, number]>> = {
  bad: [1, 0, 2],
  good: [0, 1, 2],
};
const DECISIONS: readonly ActionVote['decision'][] = ['approve', 'reject', 'abstain'];

const tables = new Map<string, readonly Cell[]>();

function policyFor(seats: readonly Seat[], options: GateOptions): GatePolicy {
  return createGatePolicy({
    panel: seats.map((seat, i) => ({ id: `dog-${i + 1}`, model: seat.model, family: seat.family, evidenceView: 'raw-logs' })),
    preApproved: { 'contain.block-source': { maxTtlSeconds: 1800, targets: ['shop-web:*'] } },
    ...(options.rule === undefined ? {} : { rule: options.rule }),
    ...(options.requireDistinctModels === undefined ? {} : { requireDistinctModels: options.requireDistinctModels }),
    ...(options.dissentAlertMin === undefined ? {} : { dissentAlertMin: options.dissentAlertMin }),
    ...(options.minOutsideFamily === undefined ? {} : { minOutsideFamily: options.minOutsideFamily }),
  });
}

/**
 * What the gate decides for every way a panel can vote. The cell at index `i`
 * is the decision when seat `k` votes `DECISIONS[digit k of i in base 3]`
 * (seat 0 is the lowest digit). Cached: the table depends only on the seats'
 * models and the gate options, not on any probability.
 *
 * `probe` changes the action being voted on, and exists so that a test can show
 * the check below working: the table is about the vote only if the gate holds
 * the action for no other reason, and it refuses to build one that does.
 */
export function gateTable(seats: readonly Seat[], options: GateOptions = {}, probe: Omit<Partial<ProposedAction>, 'votes'> = {}): readonly Cell[] {
  const key = JSON.stringify([
    seats.map((seat) => [seat.model, seat.family]),
    options.rule ?? null,
    options.requireDistinctModels ?? null,
    options.dissentAlertMin ?? null,
    options.minOutsideFamily ?? null,
    probe,
  ]);
  const cached = tables.get(key);
  if (cached !== undefined) return cached;

  const policy = policyFor(seats, options);
  const n = seats.length;
  const total = 3 ** n;
  const cells: Cell[] = [];
  for (let index = 0; index < total; index++) {
    const votes: ActionVote[] = [];
    for (let seat = 0, rest = index; seat < n; seat++, rest = Math.floor(rest / 3)) {
      votes.push({ voter: `dog-${seat + 1}`, decision: DECISIONS[rest % 3] as ActionVote['decision'] });
    }
    const action: ProposedAction = {
      id: 'risk-1',
      proposedBy: 'investigator-1',
      level: 3,
      kind: 'contain.block-source',
      target: 'shop-web:ip_000000000001',
      reason: 'A source is sending repeated executable uploads.',
      evidence: ['evt-1'],
      createdAt: '2026-10-23T10:16:00Z',
      reversible: true,
      ttlSeconds: 900,
      ...probe,
      votes,
    };
    const decision = evaluateAction(action, { now: new Date('2026-10-23T10:16:30Z') }, policy);
    // Anything on the action other than the vote would also move the outcome, and then the table would be about something else.
    const stray = decision.codes.filter((code) => !['panel-approved', 'panel-rejected', 'panel-split', 'panel-not-diverse', 'panel-one-sided', 'minority-flag'].includes(code));
    if (stray.length > 0) throw new Error(`the gate held the test action for a reason other than the vote: ${stray.join(', ')}`);
    cells.push({
      outcome: decision.outcome,
      flagged: decision.codes.includes('minority-flag'),
      split: decision.codes.includes('panel-split'),
      notDiverse: decision.codes.includes('panel-not-diverse'),
      oneSided: decision.codes.includes('panel-one-sided'),
    });
  }
  tables.set(key, cells);
  return cells;
}

function probability(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new RangeError(`${label} must be a number from 0 to 1`);
  }
  return value;
}

/** A rate given for every family or one by one, as the rate each family on the panel has. Families not named get 0. */
function ratesFor(value: number | Readonly<Record<string, number>> | undefined, label: string, families: readonly string[]): Map<string, number> {
  const rates = new Map<string, number>();
  if (typeof value !== 'object' || value === null) {
    const rate = probability(value ?? 0, label);
    for (const family of families) rates.set(family, rate);
    return rates;
  }
  for (const name of Object.keys(value)) {
    if (!families.includes(name)) throw new RangeError(`${label} names the family "${name}", which has no seat on this panel`);
  }
  for (const family of families) rates.set(family, probability(Object.hasOwn(value, family) ? value[family] : 0, `${label} for ${family}`));
  return rates;
}

function emptyOdds(): Odds {
  return { execute: 0, awaitHuman: 0, deny: 0, dissent: 0, split: 0, notDiverse: 0, oneSided: 0 };
}

function add(odds: Odds, cell: Cell, weight: number): void {
  if (cell.outcome === 'execute') odds.execute += weight;
  else if (cell.outcome === 'await-human') odds.awaitHuman += weight;
  else odds.deny += weight;
  if (cell.flagged) odds.dissent += weight;
  if (cell.split) odds.split += weight;
  if (cell.notDiverse) odds.notDiverse += weight;
  if (cell.oneSided) odds.oneSided += weight;
}

/**
 * The exact odds for a panel, summed over every way it can vote.
 *
 * A dog in an unfooled family is right with probability (1 - silent)(1 - error),
 * wrong with (1 - silent) * error, and silent with `silent`. A dog in a fooled
 * family is wrong with 1 - silent and silent with `silent`.
 */
export function panelRisk(seats: readonly Seat[], failure: FailureModel = {}, options: GateOptions = {}): PanelRisk {
  const n = seats.length;
  if (n < 2 || n > MAX_PANEL_SIZE) throw new RangeError(`a panel has 2 to ${MAX_PANEL_SIZE} dogs`);
  const families = [...new Set(seats.map((seat) => seat.family))];
  const silentOf = ratesFor(failure.silent, 'silent', families);
  const errorOf = ratesFor(failure.error, 'error', families);
  const sharedOf = ratesFor(failure.shared, 'shared', families);

  const seatsOf = families.map((family) => seats.flatMap((seat, i) => (seat.family === family ? [i] : [])));
  const table = gateTable(seats, options);
  // By family, then by status digit: right, wrong, silent.
  const okWeight = families.map((family) => {
    const silent = silentOf.get(family) as number;
    const error = errorOf.get(family) as number;
    return [(1 - silent) * (1 - error), (1 - silent) * error, silent] as const;
  });
  const foolWeight = families.map((family) => {
    const silent = silentOf.get(family) as number;
    return [0, 1 - silent, silent] as const;
  });

  const bad = emptyOdds();
  const good = emptyOdds();
  const digits = new Array<number>(n).fill(0);
  for (let index = 0; index < 3 ** n; index++) {
    for (let seat = 0, rest = index; seat < n; seat++, rest = Math.floor(rest / 3)) digits[seat] = rest % 3;

    let weight = 1;
    for (let f = 0; f < families.length; f++) {
      let ok = 1;
      let fooled = 1;
      for (const seat of seatsOf[f] as number[]) {
        const digit = digits[seat] as number;
        ok *= (okWeight[f] as readonly number[])[digit] as number;
        fooled *= (foolWeight[f] as readonly number[])[digit] as number;
      }
      const c = sharedOf.get(families[f] as string) as number;
      weight *= c * fooled + (1 - c) * ok;
    }
    if (weight === 0) continue;

    let badVote = 0;
    let goodVote = 0;
    for (let seat = n - 1; seat >= 0; seat--) {
      badVote = badVote * 3 + (VOTE_OF.bad[digits[seat] as number] as number);
      goodVote = goodVote * 3 + (VOTE_OF.good[digits[seat] as number] as number);
    }
    add(bad, table[badVote] as Cell, weight);
    add(good, table[goodVote] as Cell, weight);
  }
  return { size: n, bad, good };
}

export interface RiskRow {
  mix: Mix;
  size: number;
  /**
   * False when the make-up needs more seats than the panel has (three families on two seats), or when the
   * gate option asks for more approvals from outside the largest family than a panel this size has.
   */
  complete: boolean;
  risk: PanelRisk;
}

/** Sizes 2 to 9 for each make-up. */
export function riskTable(failure: FailureModel, options: GateOptions = {}, mixes: readonly Mix[] = MIXES): RiskRow[] {
  const rows: RiskRow[] = [];
  for (const mix of mixes) {
    for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
      const outside = options.minOutsideFamily ?? 0;
      const complete = size >= FAMILY_COUNT[mix] && size > outside;
      rows.push({ mix, size, complete, risk: panelRisk(seatsFor(mix, size), failure, complete ? options : { ...options, minOutsideFamily: 0 }) });
    }
  }
  return rows;
}

export interface NamedFailure {
  id: string;
  description: string;
  failure: FailureModel;
}

/** The failure models the report runs by default. The rates are illustrations: nobody has measured them. */
export const FAILURES: readonly NamedFailure[] = [
  { id: 'independent', description: 'Each dog is wrong 20% of the time, on its own. This is the case the design notes quote.', failure: { error: 0.2 } },
  { id: 'shared-only', description: 'Dogs never err on their own, but a whole family is fooled 10% of the time. This is the floor.', failure: { shared: 0.1 } },
  { id: 'both', description: 'Both of the above.', failure: { error: 0.2, shared: 0.1 } },
  { id: 'flaky', description: 'As "both", and one dog in ten gives no usable answer.', failure: { error: 0.2, shared: 0.1, silent: 0.1 } },
];

export function percent(value: number): string {
  if (value === 0) return '0';
  if (value < 0.0001) return '<0.01%';
  if (value < 0.01) return `${(value * 100).toFixed(2)}%`;
  return `${(value * 100).toFixed(1)}%`;
}

function grid(title: string, rows: readonly RiskRow[], mixes: readonly Mix[], pick: (risk: PanelRisk) => number): string[] {
  const width = 15;
  const lines = ['', `  ${title}`, `  ${'dogs'.padEnd(5)}${mixes.map((mix) => mix.padStart(width)).join('')}`];
  for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
    const cells = mixes.map((mix) => {
      const row = rows.find((candidate) => candidate.mix === mix && candidate.size === size);
      return (row === undefined || !row.complete ? '-' : percent(pick(row.risk))).padStart(width);
    });
    lines.push(`  ${String(size).padEnd(5)}${cells.join('')}`);
  }
  return lines;
}

export function renderRisk(failures: readonly NamedFailure[] = FAILURES, options: GateOptions = {}): string[] {
  const lines: string[] = [];
  for (const named of failures) {
    const rows = riskTable(named.failure, options);
    const rule = (options.minOutsideFamily ?? 0) > 0 ? ` [at least ${options.minOutsideFamily} approvals from outside the largest approving family]` : '';
    lines.push('', `== ${named.id}: ${named.description}${rule}`);
    lines.push(...grid('a bad proposal runs', rows, MIXES, (risk) => risk.bad.execute));
    lines.push(...grid('a good proposal runs', rows, MIXES, (risk) => risk.good.execute));
    lines.push(...grid('a bad proposal does not run, but the minority alert tells a person', rows, MIXES, (risk) => risk.bad.dissent));
  }
  lines.push(
    '',
    '  one-model: every seat the same model. one-family: a different model on each seat, all one family.',
    '  two-families, three-families: one model per family, seats handed out in turn, as planPanel does. "-": fewer seats than the make-up or the rule needs.',
  );
  return lines;
}
