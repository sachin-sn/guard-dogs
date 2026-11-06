import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  FAILURES,
  MIXES,
  gateTable,
  panelRisk,
  percent,
  renderRisk,
  riskTable,
  seatsFor,
  type GateOptions,
  type Mix,
  type Odds,
  type Seat,
} from '../eval/risk.js';
import { main } from '../eval/run.js';
import { MAX_PANEL_SIZE } from '../src/gate/policy.js';
import { createModelRegistry, planPanel, type ModelSpec } from '../src/index.js';

const close = (actual: number, expected: number): void => expect(actual).toBeCloseTo(expected, 10);
const choose = (n: number, k: number): number => {
  let result = 1;
  for (let i = 1; i <= k; i++) result = (result * (n - k + i)) / i;
  return result;
};
/** P(Binomial(n, p) is at least k). */
const atLeast = (n: number, k: number, p: number): number => {
  let sum = 0;
  for (let i = k; i <= n; i++) sum += choose(n, i) * p ** i * (1 - p) ** (n - i);
  return sum;
};
const total = (odds: Odds): number => odds.execute + odds.awaitHuman + odds.deny;

const seat = (family: string, model: string): Seat => ({ family, model });

/** The gate's rules, written out again so the table can be checked against them. */
function expectedCell(seats: readonly Seat[], votes: readonly ('approve' | 'reject' | 'abstain')[], options: GateOptions) {
  const n = seats.length;
  const required = options.rule === 'unanimous' ? n : Math.floor(n / 2) + 1;
  const alertAt = options.dissentAlertMin ?? Math.max(2, Math.ceil(n / 3));
  const approving = seats.filter((_, i) => votes[i] === 'approve');
  const rejecting = votes.filter((vote) => vote === 'reject').length;
  if (approving.length >= required) {
    const diverse = new Set(approving.map((seat) => seat.model)).size >= 2;
    if ((options.requireDistinctModels ?? true) && !diverse) {
      return { outcome: 'await-human', flagged: false, split: false, notDiverse: true, oneSided: false };
    }
    const perFamily = new Map<string, number>();
    for (const seat of approving) perFamily.set(seat.family, (perFamily.get(seat.family) ?? 0) + 1);
    const outside = approving.length - Math.max(...perFamily.values());
    if (outside < (options.minOutsideFamily ?? 0)) {
      return { outcome: 'await-human', flagged: false, split: false, notDiverse: false, oneSided: true };
    }
    return { outcome: 'execute', flagged: false, split: false, notDiverse: false, oneSided: false };
  }
  return {
    outcome: rejecting >= required ? 'deny' : 'await-human',
    flagged: approving.length >= alertAt,
    split: rejecting < required,
    notDiverse: false,
    oneSided: false,
  };
}

describe('seatsFor', () => {
  it('makes the four make-ups', () => {
    expect(seatsFor('one-model', 3)).toEqual(Array(3).fill({ family: 'family-a', model: 'model-a' }));
    expect(seatsFor('one-family', 3).map((seat) => seat.model)).toEqual(['model-1', 'model-2', 'model-3']);
    expect(new Set(seatsFor('one-family', 5).map((seat) => seat.family)).size).toBe(1);
    expect(seatsFor('two-families', 5).map((seat) => seat.family)).toEqual(['family-a', 'family-b', 'family-a', 'family-b', 'family-a']);
    expect(seatsFor('three-families', 4).map((seat) => seat.family)).toEqual(['family-a', 'family-b', 'family-c', 'family-a']);
  });

  it('gives each family one model, as the planner does', () => {
    for (const mix of ['two-families', 'three-families'] as const) {
      for (const seat of seatsFor(mix, 9)) expect(seat.model).toBe(`model-${seat.family.slice(-1)}`);
    }
  });

  it('matches the seats planPanel hands out', () => {
    const models: ModelSpec[] = ['a', 'b', 'c'].map((letter) => ({
      id: `model-${letter}`,
      provider: `provider-${letter}`,
      family: `family-${letter}`,
      tier: 'large',
      endpoint: `https://${letter}.example.invalid/v1`,
      handling: 'standard',
      maxInputChars: 10_000,
    }));
    for (const [mix, count] of [['two-families', 2], ['three-families', 3]] as const) {
      const registry = createModelRegistry(models.slice(0, count));
      for (let size = count; size <= MAX_PANEL_SIZE; size++) {
        const planned = planPanel(registry, { size, views: ['raw-logs'] }).map((member) => member.model);
        expect(seatsFor(mix, size).map((seat) => seat.model), `${mix} ${size}`).toEqual(planned);
      }
    }
  });

  it('refuses sizes the gate refuses', () => {
    for (const size of [1, 10, 2.5, Number.NaN]) expect(() => seatsFor('one-family', size)).toThrow(RangeError);
  });
});

describe('gateTable', () => {
  it('has a cell for every way of voting', () => {
    for (let size = 2; size <= 7; size++) expect(gateTable(seatsFor('one-family', size))).toHaveLength(3 ** size);
  });

  it('agrees with the rules of the gate for every way of voting', () => {
    const optionSets: GateOptions[] = [
      {},
      { rule: 'unanimous' },
      { requireDistinctModels: false },
      { dissentAlertMin: 1 },
      { dissentAlertMin: 2, rule: 'majority', requireDistinctModels: true },
      { minOutsideFamily: 1 },
      { minOutsideFamily: 2 },
      { minOutsideFamily: 2, requireDistinctModels: false, rule: 'unanimous' },
    ];
    // Panels that are not the same read from either end, so a table indexed the wrong way round shows.
    const uneven: [string, Seat[]][] = [
      ['m1 m1 m2', [seat('x', 'm1'), seat('x', 'm1'), seat('y', 'm2')]],
      ['m1 m2 m2 m3', [seat('x', 'm1'), seat('y', 'm2'), seat('y', 'm2'), seat('z', 'm3')]],
      ['m1 m1 m1 m2 m2', [seat('x', 'm1'), seat('x', 'm1'), seat('x', 'm1'), seat('y', 'm2'), seat('y', 'm2')]],
    ];
    const arrangements: [string, Seat[]][] = [
      ...MIXES.flatMap((mix) => [2, 3, 4, 5, 6].map((size): [string, Seat[]] => [`${mix} ${size}`, seatsFor(mix, size)])),
      ...uneven,
    ];
    for (const options of optionSets) {
      for (const [name, seats] of arrangements) {
        // The gate refuses a rule that asks for as many outside approvals as the panel has seats.
        if ((options.minOutsideFamily ?? 0) >= seats.length) continue;
        const table = gateTable(seats, options);
        for (let index = 0; index < 3 ** seats.length; index++) {
          const votes: ('approve' | 'reject' | 'abstain')[] = [];
          for (let at = 0, rest = index; at < seats.length; at++, rest = Math.floor(rest / 3)) {
            votes.push((['approve', 'reject', 'abstain'] as const)[rest % 3] as 'approve');
          }
          expect(table[index], `${name} ${JSON.stringify(options)} ${votes.join(',')}`).toEqual(expectedCell(seats, votes, options));
        }
      }
    }
  }, 30_000);

  it('puts seat 0 in the lowest digit and approve at 0, reject at 1, abstain at 2', () => {
    const table = gateTable(seatsFor('two-families', 3));
    // Seats A, B, A. Index 0 is all approve; 2 is seat 0 abstaining, the others approving.
    expect(table[0]?.outcome).toBe('execute');
    expect(table[2]?.outcome).toBe('execute');
    // Seat 0 rejects (digit 1) and the others approve: two approvals from A and B.
    expect(table[1]?.outcome).toBe('execute');
    // Seats 1 and 2 reject: index 3 + 9.
    expect(table[3 + 9]?.outcome).toBe('deny');
  });

  it('refuses to build a table when the gate holds the action for a reason other than the vote', () => {
    const seats = seatsFor('one-family', 3);
    for (const probe of [{ level: 4 }, { ttlSeconds: 3600 }, { target: 'elsewhere:x' }, { kind: 'contain.rate-limit' }] as const) {
      expect(() => gateTable(seats, {}, probe), JSON.stringify(probe)).toThrow(/for a reason other than the vote/);
    }
    // And not when the probe leaves the vote as the only reason.
    expect(gateTable(seats, {}, { reason: 'Another sentence.' })[0]?.outcome).toBe('execute');
  });

  it('keeps the table of a rule on families apart from the plain one, and tells families apart', () => {
    const seats = [seat('x', 'm1'), seat('x', 'm2'), seat('y', 'm3')];
    // Seats 0 and 1 approve and seat 2 rejects: index 0 + 0 + 9.
    expect(gateTable(seats)[9]?.outcome).toBe('execute');
    expect(gateTable(seats, { minOutsideFamily: 1 })[9]).toMatchObject({ outcome: 'await-human', oneSided: true, notDiverse: false });
    // The same models in other families give another table.
    const apart = [seat('x', 'm1'), seat('y', 'm2'), seat('z', 'm3')];
    expect(gateTable(apart, { minOutsideFamily: 1 })[9]?.outcome).toBe('execute');
  });

  it('keeps a probed table apart from the plain one', () => {
    const seats = seatsFor('one-family', 4);
    const plain = gateTable(seats);
    expect(gateTable(seats, {}, { reason: 'Another sentence.' })).not.toBe(plain);
    expect(gateTable(seats)).toBe(plain);
  });

  it('keeps the tables for different options apart', () => {
    const seats = seatsFor('one-model', 3);
    expect(gateTable(seats)[0]?.outcome).toBe('await-human');
    expect(gateTable(seats, { requireDistinctModels: false })[0]?.outcome).toBe('execute');
    expect(gateTable(seats, { rule: 'unanimous' })[1]?.outcome).not.toBe('execute');
    // Seat 0 approves and the other two reject: index 0 + 3 + 9.
    expect(gateTable(seats, { dissentAlertMin: 1 })[12]?.flagged).toBe(true);
    expect(gateTable(seats)[12]?.flagged).toBe(false);
  });

  it('is told apart by the models on the seats, not by their families', () => {
    const same = [{ family: 'x', model: 'm' }, { family: 'y', model: 'm' }];
    const different = [{ family: 'x', model: 'm1' }, { family: 'x', model: 'm2' }];
    expect(gateTable(same)[0]?.notDiverse).toBe(true);
    expect(gateTable(different)[0]?.outcome).toBe('execute');
  });
});

describe('panelRisk, by hand', () => {
  it('two dogs of two models, independent errors', () => {
    const e = 0.2;
    const { bad, good } = panelRisk(seatsFor('two-families', 2), { error: e });
    close(bad.execute, e * e);
    close(bad.deny, (1 - e) ** 2);
    close(bad.awaitHuman, 2 * e * (1 - e));
    close(bad.split, 2 * e * (1 - e));
    close(bad.dissent, 0);
    close(good.execute, (1 - e) ** 2);
    close(good.deny, e * e);
    close(good.awaitHuman, 2 * e * (1 - e));
  });

  it('three dogs: the majority is two, and one approval is not an alert', () => {
    const e = 0.15;
    const { bad } = panelRisk(seatsFor('one-family', 3), { error: e });
    close(bad.execute, 3 * e * e * (1 - e) + e ** 3);
    close(bad.deny, 3 * e * (1 - e) ** 2 + (1 - e) ** 3);
    close(bad.awaitHuman, 0);
    close(bad.dissent, 0);
  });

  it('seven dogs: three approving and four rejecting is denied and a person is told', () => {
    const e = 0.2;
    const { bad } = panelRisk(seatsFor('one-family', 7), { error: e });
    close(bad.dissent, choose(7, 3) * e ** 3 * (1 - e) ** 4);
    close(bad.execute, atLeast(7, 4, e));
    // With nobody silent, 3 approvals + 4 rejections is the only way to be flagged: 4 approvals runs, 2 does not alert.
    close(bad.deny, atLeast(7, 4, 1 - e));
    close(bad.awaitHuman, 0);
  });

  it('five dogs: three needed, two approvals alert a person', () => {
    const e = 0.3;
    const { bad } = panelRisk(seatsFor('one-family', 5), { error: e });
    close(bad.dissent, choose(5, 2) * e ** 2 * (1 - e) ** 3);
    close(bad.execute, atLeast(5, 3, e));
  });

  it('reproduces the figures in the design notes: a majority is right 90, 94, 97 and 98 percent of the time', () => {
    const right = [3, 5, 7, 9].map((size) => 1 - panelRisk(seatsFor('one-family', size), { error: 0.2 }).bad.execute);
    expect(right.map((value) => Math.round(value * 100))).toEqual([90, 94, 97, 98]);
    // The same numbers for the good case: the rule is symmetric.
    const found = [3, 5, 7, 9].map((size) => panelRisk(seatsFor('one-family', size), { error: 0.2 }).good.execute);
    expect(found.map((value) => Math.round(value * 100))).toEqual([90, 94, 97, 98]);
  });

  it('a silent dog never agrees', () => {
    const s = 0.1;
    const { bad, good } = panelRisk(seatsFor('two-families', 2), { silent: s });
    close(bad.execute, 0);
    close(good.execute, (1 - s) ** 2);
    close(good.awaitHuman, 1 - (1 - s) ** 2);
    close(good.deny, 0);
  });

  it('one family, shared failure only: the panel is as good as one dog, however big', () => {
    for (const c of [0.05, 0.1, 0.3]) {
      for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
        const { bad, good } = panelRisk(seatsFor('one-family', size), { shared: c });
        close(bad.execute, c);
        close(good.execute, 1 - c);
      }
    }
  });

  it('two families: one fooled family cannot act alone, because its approvals share a model', () => {
    const c = 0.1;
    for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
      const { bad } = panelRisk(seatsFor('two-families', size), { shared: c });
      close(bad.execute, c * c);
      // The fooled family alone has a majority of the seats only on an odd panel, and it is one model.
      close(bad.notDiverse, size % 2 === 1 ? c * (1 - c) : 0);
    }
  });

  it('two families on four seats: a fooled family has two of the four, which is a flag but not a majority', () => {
    const c = 0.1;
    const { bad } = panelRisk(seatsFor('two-families', 4), { shared: c });
    close(bad.execute, c * c);
    close(bad.dissent, 2 * c * (1 - c));
    close(bad.awaitHuman, 2 * c * (1 - c));
    close(bad.deny, (1 - c) ** 2);
  });

  it('three families: any two fooled form a majority of three, and of five', () => {
    const c = 0.1;
    const pair = 3 * c * c * (1 - c) + c ** 3;
    for (const size of [3, 5, 6, 7, 8, 9]) close(panelRisk(seatsFor('three-families', size), { shared: c }).bad.execute, pair);
    // On four seats (A, B, C, A) the pair B and C has only two.
    close(panelRisk(seatsFor('three-families', 4), { shared: c }).bad.execute, 2 * c * c * (1 - c) + c ** 3);
  });

  it('a panel that reads differently from each end: two seats of one model and one of another', () => {
    const c = 0.1;
    const seats = [seat('x', 'm1'), seat('x', 'm1'), seat('y', 'm2')];
    const { bad, good } = panelRisk(seats, { shared: c });
    // Only both families fooled approve with two models. Family x alone has the majority but one model.
    close(bad.execute, c * c);
    close(bad.notDiverse, c * (1 - c));
    close(bad.awaitHuman, c * (1 - c));
    close(bad.deny, (1 - c) ** 2 + c * (1 - c));
    // A real attack: x right and y wrong still has two approvals from one model.
    close(good.execute, (1 - c) ** 2);
    close(good.notDiverse, (1 - c) * c);
    // The same panel the other way round gives the same answer.
    const reversed = panelRisk([...seats].reverse(), { shared: c });
    close(reversed.bad.execute, bad.execute);
    close(reversed.bad.notDiverse, bad.notDiverse);
    close(reversed.good.execute, good.execute);
  });

  it('with a rule on outside approvals: four dogs of two families need all four to agree', () => {
    const e = 0.2;
    const { bad, good } = panelRisk(seatsFor('two-families', 4), { error: e }, { minOutsideFamily: 2 });
    // Three approvals are two of one family and one of the other: one outside. Only all four give two.
    close(bad.execute, e ** 4);
    close(bad.oneSided, 4 * e ** 3 * (1 - e));
    close(good.execute, (1 - e) ** 4);
    close(good.oneSided, 4 * (1 - e) ** 3 * e);
    close(bad.notDiverse, 0);
  });

  it('with a rule on outside approvals, a panel of one family never acts', () => {
    for (let size = 3; size <= MAX_PANEL_SIZE; size++) {
      const { bad, good } = panelRisk(seatsFor('one-family', size), { error: 0.2, shared: 0.1 }, { minOutsideFamily: 1 });
      expect(bad.execute).toBe(0);
      expect(good.execute).toBe(0);
      expect(bad.oneSided).toBeGreaterThan(0);
    }
  }, 30_000);

  it('with a rule on outside approvals, a fooled family of five needs three accomplices on nine dogs', () => {
    // Family A has five seats and B four. Fooled A alone is five approvals, none outside, and one model.
    const shared = panelRisk(seatsFor('two-families', 9), { shared: 0.1 }, { minOutsideFamily: 2 });
    close(shared.bad.execute, 0.01);
    // With A certainly fooled and B erring at 20% on its own: B needs two or more wrong dogs of four.
    const { bad } = panelRisk(seatsFor('two-families', 9), { error: 0.2, shared: { 'family-a': 1 } }, { minOutsideFamily: 2 });
    close(bad.execute, 1 - 0.8 ** 4 - 4 * 0.2 * 0.8 ** 3);
    close(bad.oneSided, 4 * 0.2 * 0.8 ** 3);
    // Under the present rule one accomplice is enough.
    close(panelRisk(seatsFor('two-families', 9), { error: 0.2, shared: { 'family-a': 1 } }).bad.execute, 1 - 0.8 ** 4);
  });

  it('agrees with a separate enumeration of the same panels', () => {
    const nine = panelRisk(seatsFor('two-families', 9), { error: 0.2, shared: 0.1 }, { minOutsideFamily: 2 });
    close(nine.bad.execute, 0.06291122176);
    close(nine.good.execute, 0.77630275584);
    const seven = panelRisk(seatsFor('three-families', 7), { error: 0.2, shared: 0.1, silent: 0.1 }, { minOutsideFamily: 2 });
    close(seven.bad.execute, 0.08089384504062007);
    close(seven.good.execute, 0.7274172687895798);
  });

  it('a stricter rule never lets more through', () => {
    for (const failure of [{ error: 0.2 }, { error: 0.2, shared: 0.1 }, { shared: 0.3, silent: 0.1 }]) {
      for (const mix of MIXES) {
        for (const size of [5, 8]) {
          let last = 2;
          for (const outside of [0, 1, 2, 3]) {
            const risk = panelRisk(seatsFor(mix, size), failure, { minOutsideFamily: outside });
            expect(risk.bad.execute).toBeLessThanOrEqual(last + 1e-12);
            expect(risk.good.execute).toBeLessThanOrEqual(1 + 1e-12);
            last = risk.bad.execute;
            close(total(risk.bad), 1);
            close(total(risk.good), 1);
          }
        }
      }
    }
  }, 30_000);

  it('on the planner shape, one outside approval is the rule the gate already has', () => {
    for (const mix of ['two-families', 'three-families'] as const) {
      for (let size = 3; size <= MAX_PANEL_SIZE; size++) {
        const plain = panelRisk(seatsFor(mix, size), { error: 0.2, shared: 0.1 });
        const one = panelRisk(seatsFor(mix, size), { error: 0.2, shared: 0.1 }, { minOutsideFamily: 1 });
        close(one.bad.execute, plain.bad.execute);
        close(one.good.execute, plain.good.execute);
      }
    }
  });

  it('one model never acts alone, whatever its seats say', () => {
    for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
      const { bad, good } = panelRisk(seatsFor('one-model', size), { error: 0.1, shared: 0.1, silent: 0.05 });
      expect(bad.execute).toBe(0);
      expect(good.execute).toBe(0);
      expect(bad.notDiverse).toBeGreaterThan(0);
    }
  }, 30_000);

  it('without the diversity rule, one model can act', () => {
    const { good } = panelRisk(seatsFor('one-model', 3), { error: 0.2 }, { requireDistinctModels: false });
    close(good.execute, atLeast(3, 2, 0.8));
  });

  it('unanimous: every dog must agree', () => {
    const e = 0.2;
    const { bad, good } = panelRisk(seatsFor('one-family', 4), { error: e }, { rule: 'unanimous' });
    close(bad.execute, e ** 4);
    close(good.execute, (1 - e) ** 4);
  });

  it('a family named by its own rate', () => {
    const seats = seatsFor('two-families', 2);
    // Family A is certainly fooled and family B never: A approves, B rejects, and with two dogs that waits for a person.
    const { bad, good } = panelRisk(seats, { shared: { 'family-a': 1 } });
    close(bad.execute, 0);
    close(bad.awaitHuman, 1);
    close(good.awaitHuman, 1);
    // Naming no family is the same as zero.
    close(panelRisk(seats, { shared: {} }).bad.deny, 1);
  });
});

describe('panelRisk, in general', () => {
  const grid: { error: number; shared: number; silent: number }[] = [];
  for (const error of [0, 0.05, 0.2, 0.5, 1]) for (const shared of [0, 0.1, 0.6, 1]) for (const silent of [0, 0.1, 0.9, 1]) grid.push({ error, shared, silent });

  it('the three outcomes add up to one, for good and bad, for every panel', () => {
    for (const failure of grid) {
      for (const mix of MIXES) {
        for (let size = 2; size <= MAX_PANEL_SIZE; size += size < 5 ? 1 : 2) {
          const risk = panelRisk(seatsFor(mix, size), failure);
          close(total(risk.bad), 1);
          close(total(risk.good), 1);
        }
      }
    }
  }, 30_000);

  it('the parts are inside the whole', () => {
    for (const failure of grid) {
      for (const mix of MIXES) {
        const { bad, good } = panelRisk(seatsFor(mix, 7), failure);
        for (const odds of [bad, good]) {
          expect(odds.dissent).toBeLessThanOrEqual(odds.awaitHuman + odds.deny + 1e-12);
          expect(odds.split).toBeLessThanOrEqual(odds.awaitHuman + 1e-12);
          expect(odds.notDiverse).toBeLessThanOrEqual(odds.awaitHuman + 1e-12);
          for (const value of Object.values(odds)) expect(value).toBeGreaterThanOrEqual(-1e-12);
        }
      }
    }
  });

  it('with no failures at all, a bad proposal is denied and a good one runs', () => {
    for (const mix of ['one-family', 'two-families', 'three-families'] as const) {
      for (let size = 3; size <= MAX_PANEL_SIZE; size++) {
        const { bad, good } = panelRisk(seatsFor(mix, size));
        close(bad.deny, 1);
        close(good.execute, 1);
      }
    }
  });

  it('with every dog wrong, the roles swap', () => {
    const { bad, good } = panelRisk(seatsFor('one-family', 5), { error: 1 });
    close(bad.execute, 1);
    close(good.deny, 1);
  });

  it('with every dog silent, nothing ever runs and a person is asked', () => {
    for (const mix of MIXES) {
      const { bad, good } = panelRisk(seatsFor(mix, 5), { silent: 1, error: 0.3, shared: 0.5 });
      close(bad.awaitHuman, 1);
      close(good.awaitHuman, 1);
      close(bad.dissent, 0);
    }
  });

  it('more independent error never makes a bad proposal safer', () => {
    for (const mix of ['one-family', 'two-families'] as const) {
      for (const size of [3, 5, 9]) {
        let last = -1;
        for (const error of [0, 0.1, 0.2, 0.4, 0.6, 1]) {
          const now = panelRisk(seatsFor(mix, size), { error, shared: 0.1 }).bad.execute;
          expect(now).toBeGreaterThanOrEqual(last - 1e-12);
          last = now;
        }
      }
    }
  });

  it('shared failure sets a floor that more dogs of the same family do not lower', () => {
    const floor = panelRisk(seatsFor('one-family', 9), { shared: 0.1 }).bad.execute;
    for (let size = 3; size <= 9; size++) {
      expect(panelRisk(seatsFor('one-family', size), { shared: 0.1, error: 0.2 }).bad.execute).toBeGreaterThanOrEqual(floor - 1e-12);
    }
  });

  it('a second family lowers the floor from c to c squared', () => {
    close(panelRisk(seatsFor('one-family', 5), { shared: 0.1 }).bad.execute, 0.1);
    close(panelRisk(seatsFor('two-families', 5), { shared: 0.1 }).bad.execute, 0.01);
  });

  it('size alone is no help to a bad panel: with the shared failure, a bigger two-family panel can be worse', () => {
    const failure = { error: 0.2, shared: 0.1 };
    const small = panelRisk(seatsFor('two-families', 3), failure).bad.execute;
    const large = panelRisk(seatsFor('two-families', 9), failure).bad.execute;
    // Nine dogs let one wrong dog of the other family satisfy the diversity rule for a fooled family.
    expect(large).toBeGreaterThan(small);
  });

  it('an even panel is safer and less useful than the odd one below it', () => {
    const failure = { error: 0.2 };
    for (const size of [3, 5, 7]) {
      const odd = panelRisk(seatsFor('one-family', size), failure);
      const even = panelRisk(seatsFor('one-family', size + 1), failure);
      expect(even.bad.execute).toBeLessThan(odd.bad.execute);
      expect(even.good.execute).toBeLessThan(odd.good.execute);
    }
  });

  it('refuses rates and panels that make no sense', () => {
    const seats = seatsFor('one-family', 3);
    for (const bad of [-0.1, 1.1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => panelRisk(seats, { error: bad })).toThrow(/error must be a number from 0 to 1/);
      expect(() => panelRisk(seats, { silent: bad })).toThrow(/silent must be a number from 0 to 1/);
      expect(() => panelRisk(seats, { shared: bad })).toThrow(/shared must be a number from 0 to 1/);
      expect(() => panelRisk(seats, { shared: { 'family-a': bad } })).toThrow(/shared for family-a must be a number/);
    }
    expect(() => panelRisk(seats, { error: '0.1' as unknown as number })).toThrow(RangeError);
    expect(() => panelRisk(seats, { shared: { 'family-z': 0.1 } })).toThrow(/family-z/);
    expect(() => panelRisk(seats.slice(0, 1))).toThrow(/a panel has 2 to 9 dogs/);
    expect(() => panelRisk(Array.from({ length: 10 }, (_, i) => ({ family: 'x', model: `m${i}` })))).toThrow(/a panel has 2 to 9 dogs/);
    expect(() => panelRisk([])).toThrow(/a panel has 2 to 9 dogs/);
  });

  it('reports the size', () => {
    expect(panelRisk(seatsFor('one-family', 6)).size).toBe(6);
  });
});

describe('riskTable and the report', () => {
  it('has a row for every make-up and size', () => {
    const rows = riskTable({ error: 0.2 });
    expect(rows).toHaveLength(MIXES.length * (MAX_PANEL_SIZE - 1));
    expect(rows.filter((row) => !row.complete).map((row) => `${row.mix} ${row.size}`)).toEqual(['three-families 2']);
    for (const row of rows) expect(row.risk.size).toBe(row.size);
  });

  it('leaves out the sizes a rule on outside approvals cannot be met on', () => {
    const rows = riskTable({ error: 0.2 }, { minOutsideFamily: 2 });
    expect(rows.filter((row) => !row.complete).map((row) => `${row.mix} ${row.size}`)).toEqual([
      'one-model 2',
      'one-family 2',
      'two-families 2',
      'three-families 2',
    ]);
    // Worked out separately, by enumerating the same panel with the rule written out again.
    expect(rows.find((row) => row.mix === 'two-families' && row.size === 9)?.risk.bad.execute).toBeCloseTo(0.016042496, 8);
  });

  it('can be limited to some make-ups', () => {
    const rows = riskTable({ error: 0.2 }, {}, ['two-families']);
    expect(new Set(rows.map((row) => row.mix))).toEqual(new Set<Mix>(['two-families']));
  });

  it('passes the gate options on', () => {
    const rows = riskTable({ error: 0.2 }, { rule: 'unanimous' }, ['one-family']);
    close(rows.find((row) => row.size === 3)?.risk.bad.execute ?? -1, 0.2 ** 3);
  });

  it('formats percentages so small numbers stay visible', () => {
    expect(percent(0)).toBe('0');
    expect(percent(0.00001)).toBe('<0.01%');
    expect(percent(0.0001)).toBe('0.01%');
    expect(percent(0.0049)).toBe('0.49%');
    expect(percent(0.01)).toBe('1.0%');
    expect(percent(0.1044)).toBe('10.4%');
    expect(percent(1)).toBe('100.0%');
  });

  it('prints three grids for each failure model and says what the make-ups are', () => {
    const lines = renderRisk(FAILURES.slice(0, 2));
    const text = lines.join('\n');
    expect(lines.filter((line) => line.startsWith('== '))).toHaveLength(2);
    expect(text.match(/a bad proposal runs/g)).toHaveLength(2);
    expect(text.match(/a good proposal runs/g)).toHaveLength(2);
    expect(text.match(/the minority alert tells a person/g)).toHaveLength(2);
    expect(text).toContain('one-model: every seat the same model');
    for (const mix of MIXES) expect(text).toContain(mix);
    // Panel sizes 2 to 9 in every grid, and a dash where three families do not fit.
    expect(lines.filter((line) => /^ {2}[2-9] {4}/.test(line))).toHaveLength(8 * 6);
    expect(lines.filter((line) => /^ {2}2 .*-$/.test(line))).toHaveLength(6);
  });

  it('lays each grid out under its own title, with the right quantity in it', () => {
    const lines = renderRisk(FAILURES.slice(0, 1));
    const grid = (title: string): string[] => {
      const at = lines.indexOf(`  ${title}`);
      expect(at, title).toBeGreaterThan(0);
      return lines.slice(at + 1, at + 10);
    };
    const bad = grid('a bad proposal runs');
    const good = grid('a good proposal runs');
    const alert = grid('a bad proposal does not run, but the minority alert tells a person');
    for (const rows of [bad, good, alert]) expect(rows[0]).toBe('  dogs       one-model     one-family   two-families three-families');
    expect(bad[1]).toBe('  2                  0           4.0%           4.0%              -');
    expect(bad[2]).toBe('  3                  0          10.4%           7.2%          10.4%');
    expect(good[2]).toBe('  3                  0          89.6%          76.8%          89.6%');
    expect(alert[5]).toBe('  6              32.8%          32.8%          32.8%          32.8%');
    expect(alert[6]).toBe('  7              11.5%          11.5%          11.5%          11.5%');
    // Each grid is a blank line, a title, a header and eight rows.
    expect(lines.indexOf('  a good proposal runs') - lines.indexOf('  a bad proposal runs')).toBe(11);
    expect(lines[lines.indexOf('  a bad proposal runs') - 1]).toBe('');
  });

  it('explains the make-ups at the end', () => {
    const lines = renderRisk(FAILURES.slice(0, 1));
    expect(lines.at(-2)).toBe('  one-model: every seat the same model. one-family: a different model on each seat, all one family.');
    expect(lines.at(-1)).toBe('  two-families, three-families: one model per family, seats handed out in turn, as planPanel does. "-": fewer seats than the make-up or the rule needs.');
    expect(lines.at(-3)).toBe('');
  });

  it('says in the heading when the gate is asked for outside approvals, and shows its effect', () => {
    const plain = renderRisk(FAILURES.slice(0, 1)).filter((line) => line.startsWith('== '));
    expect(plain[0]).not.toContain('outside');
    const lines = renderRisk([{ id: 'x', description: 'd', failure: { error: 0.2, shared: 0.1 } }], { minOutsideFamily: 2 });
    expect(lines.filter((line) => line.startsWith('== '))).toEqual(['== x: d [at least 2 approvals from outside the largest approving family]']);
    expect(lines.indexOf('  a bad proposal runs') + 2).toBeLessThan(lines.length);
    // Nine dogs of two families: 6.3% against 13.9% without the rule.
    expect(lines.join('\n')).toMatch(/^ {2}9 .* 0 .* 0 .* 6\.3% .* 12\.6%$/m);
    expect(lines.join('\n')).toMatch(/^ {2}2 .* - .* - .* - .* -$/m);
  });

  it('reports all four default failure models when asked for none in particular', () => {
    expect(renderRisk().filter((line) => line.startsWith('== '))).toHaveLength(4);
  });

  it('passes the gate options to every grid', () => {
    const lines = renderRisk(FAILURES.slice(0, 1), { rule: 'unanimous' });
    const at = lines.indexOf('  a bad proposal runs');
    // Three dogs that must all agree: 0.2 cubed.
    expect(lines[at + 3]).toMatch(/^ {2}3 .* 0\.80% .* 0\.80% .* 0\.80%$/);
  }, 30_000);

  it('shows the independent case with the figures from the design notes', () => {
    const text = renderRisk(FAILURES.slice(0, 1)).join('\n');
    expect(text).toMatch(/^ {2}3 .* 10\.4% .*7\.2% .*10\.4%$/m);
    expect(text).toMatch(/^ {2}9 .* 2\.0% .*1\.9% .*2\.0%$/m);
  });

  it('the default failure models are what the docs say they are', () => {
    expect(FAILURES.map((named) => named.id)).toEqual(['independent', 'shared-only', 'both', 'flaky']);
    expect(FAILURES[0]?.failure).toEqual({ error: 0.2 });
    expect(FAILURES[1]?.failure).toEqual({ shared: 0.1 });
    expect(FAILURES[2]?.failure).toEqual({ error: 0.2, shared: 0.1 });
    expect(FAILURES[3]?.failure).toEqual({ error: 0.2, shared: 0.1, silent: 0.1 });
  });
});

describe('npm run eval -- --risk', () => {
  const run = async (args: string[]): Promise<string[]> => {
    const lines: string[] = [];
    await main(args, (line) => lines.push(line));
    return lines;
  };

  it('reports every default failure model and says the rates are inputs', async () => {
    const lines = await run(['--risk']);
    expect(lines[0]).toMatch(/not measurements/);
    expect(lines.filter((line) => line.startsWith('== '))).toHaveLength(FAILURES.length);
  });

  it('takes its own rates', async () => {
    const lines = await run(['--risk', '--error', '0.3', '--shared', '0.05', '--silent', '0']);
    expect(lines.filter((line) => line.startsWith('== '))).toEqual(['== custom: error 0.3, shared 0.05, silent 0.']);
  });

  it('takes a rule on outside approvals', async () => {
    const lines = await run(['--risk', '--error', '0.2', '--shared', '0.1', '--outside', '2']);
    expect(lines.filter((line) => line.startsWith('== '))).toEqual([
      '== custom: error 0.2, shared 0.1, silent 0. [at least 2 approvals from outside the largest approving family]',
    ]);
    expect(lines.join('\n')).toMatch(/^ {2}9 .* 6\.3% .* 12\.6%$/m);
    // Zero is the gate as it is.
    const zero = await run(['--risk', '--error', '0.2', '--outside', '0']);
    expect(zero.filter((line) => line.startsWith('== '))).toEqual(['== custom: error 0.2, shared 0, silent 0.']);
  });

  it('refuses an outside count that is missing or not a whole number in range', async () => {
    for (const args of [['--outside'], ['--outside', ''], ['--outside', 'x'], ['--outside', '1.5'], ['--outside', '-1'], ['--outside', '9']]) {
      await expect(run(['--risk', ...args]), args.join(' ')).rejects.toThrow(/--outside needs a whole number from 0 to 8/);
    }
    expect((await run(['--risk', '--error', '0.1', '--outside', '8'])).length).toBeGreaterThan(10);
  }, 30_000);

  it('accepts the extremes, 0 and 1', async () => {
    expect((await run(['--risk', '--error', '1'])).filter((line) => line.startsWith('== '))).toEqual(['== custom: error 1, shared 0, silent 0.']);
    expect((await run(['--risk', '--error', '0', '--silent', '1'])).filter((line) => line.startsWith('== '))).toEqual(['== custom: error 0, shared 0, silent 1.']);
  });

  it('says in its heading which rates it used, zero for the ones not given', async () => {
    expect((await run(['--risk', '--error', '0.2'])).filter((line) => line.startsWith('== '))).toEqual(['== custom: error 0.2, shared 0, silent 0.']);
    expect((await run(['--risk', '--silent', '0.4'])).filter((line) => line.startsWith('== '))).toEqual(['== custom: error 0, shared 0, silent 0.4.']);
  });

  it('a rate you leave out is zero', async () => {
    const lines = await run(['--risk', '--shared', '0.1']);
    expect(lines.filter((line) => line.startsWith('== '))).toEqual(['== custom: error 0, shared 0.1, silent 0.']);
    expect(lines.join('\n')).toMatch(/^ {2}5 .* 10\.0% .*1\.0% /m);
  });

  it('refuses a rate that is missing, out of range or not a number', async () => {
    for (const args of [['--error'], ['--error', ''], ['--error', 'x'], ['--shared', '1.5'], ['--silent', '-1'], ['--error', '0.1', '--shared']]) {
      await expect(run(['--risk', ...args]), args.join(' ')).rejects.toThrow(/needs a number from 0 to 1/);
    }
  });

  it('writes the rows for the rule it was asked to report', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-'));
    try {
      const out = path.join(dir, 'risk.json');
      await run(['--risk', '--error', '0.2', '--shared', '0.1', '--outside', '2', '--json', out]);
      const parsed = JSON.parse(fs.readFileSync(out, 'utf8')) as { rows: { mix: string; size: number; complete: boolean; risk: { bad: Odds } }[] }[];
      const row = parsed[0]?.rows.find((entry) => entry.mix === 'two-families' && entry.size === 9);
      close(row?.risk.bad.execute ?? -1, 0.06291122176);
      expect(parsed[0]?.rows.find((entry) => entry.size === 2)?.complete).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('writes the rows as JSON', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-'));
    try {
      const out = path.join(dir, 'risk.json');
      const lines = await run(['--risk', '--error', '0.2', '--json', out]);
      expect(lines.at(-1)).toBe(`\nwrote ${out}`);
      const parsed = JSON.parse(fs.readFileSync(out, 'utf8')) as { id: string; rows: { mix: string; size: number; risk: { bad: Odds } }[] }[];
      expect(parsed).toHaveLength(1);
      expect(parsed[0]?.id).toBe('custom');
      expect(parsed[0]?.rows).toHaveLength(MIXES.length * 8);
      const row = parsed[0]?.rows.find((entry) => entry.mix === 'one-family' && entry.size === 3);
      close(row?.risk.bad.execute ?? -1, 3 * 0.2 ** 2 * 0.8 + 0.2 ** 3);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
