import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_LIMITS,
  callCount,
  collectCases,
  failureFor,
  figures,
  inputsOf,
  makeups,
  measure,
  plan,
  renderMeasured,
  renderPlan,
  tallyInvestigations,
  tallyTriage,
  tallyVotes,
  wilson,
  type Collected,
  type Inputs,
  type Participant,
  type Plan,
  type VoteCase,
  type VoteRecord,
} from '../eval/live.js';
import { corpus } from '../eval/corpus.js';
import { panelRisk, seatsFor } from '../eval/risk.js';
import type { Scenario } from '../eval/scenario.js';
import { block } from '../eval/sim.js';
import { main } from '../examples/profile.js';
import { ModelError, buildVotePrompt, createModelRegistry, type ModelClient, type ModelRequest } from '../src/index.js';

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const asRecord = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});

// Built once, before any test is defined: some describe blocks make their plan as they are read.
const collected: Collected = await collectCases();

// ---- the cases ---------------------------------------------------------------------------

describe('the labelled cases', () => {
  it('come from the corpus: what is in it, by label and by why', () => {
    const count = (label: string, source: string): number => collected.votes.filter((entry) => entry.label === label && entry.source === source).length;
    expect(collected.votes).toHaveLength(34);
    expect(count('good', 'right')).toBe(15);
    expect(count('bad', 'decoy')).toBe(15);
    expect(count('bad', 'forbidden')).toBe(2);
    expect(count('bad', 'harmless')).toBe(2);
    expect(collected.investigations).toHaveLength(18);
    expect(collected.triage).toHaveLength(18);
  });

  it('are the same every time, so a plan is the same every time', async () => {
    const again = await collectCases();
    // The recorded triage and investigation prompts carry a random token in their block tags; nothing else may differ.
    const plain = (value: unknown): string => JSON.stringify(value).replace(/<(\\?\/?)([a-z]+)-[A-Za-z0-9]{8,64}>/g, '<$1$2>');
    expect(plain(again)).toBe(plain(collected));
    expect(plan(again).votes.map((entry) => entry.id)).toEqual(plan(collected).votes.map((entry) => entry.id));
  });

  it('give every case its own id', () => {
    for (const list of [collected.votes, collected.investigations, collected.triage]) {
      expect(new Set(list.map((entry) => entry.id)).size).toBe(list.length);
    }
  });

  it('label a proposal good only when the scenario wrote it down as the answer', async () => {
    const { corpus } = await import('../eval/corpus.js');
    for (const entry of collected.votes.filter((candidate) => candidate.label === 'good')) {
      const scenario = corpus.find((candidate) => candidate.id === entry.scenario);
      expect(scenario, entry.id).toBeDefined();
      const { kind, target } = entry.task.action;
      // A client address is written `ip:...` in the scenario and is a pseudonym in the system.
      const written = scenario?.correct.some((containment) => containment.kind === kind && (containment.target === target || (containment.target.startsWith('ip:') && target.startsWith('ip_'))));
      expect(written, entry.id).toBe(true);
    }
  });

  it('label a proposal bad only for a reason that does not need arguing', async () => {
    const { corpus } = await import('../eval/corpus.js');
    for (const entry of collected.votes.filter((candidate) => candidate.source === 'harmless')) {
      expect(corpus.find((candidate) => candidate.id === entry.scenario)?.correct, entry.id).toEqual([]);
    }
    for (const entry of collected.votes.filter((candidate) => candidate.source === 'forbidden')) {
      expect(corpus.find((candidate) => candidate.id === entry.scenario)?.forbidden?.length, entry.id).toBeGreaterThan(0);
      expect(entry.task.action.target, entry.id).toMatch(/^ip_[0-9a-f]{12}$/);
    }
  });

  it('give each good proposal a decoy twin that differs only in the target, and names nothing the evidence mentions', () => {
    const decoys = collected.votes.filter((entry) => entry.source === 'decoy');
    const goods = collected.votes.filter((entry) => entry.source === 'right');
    expect(decoys).toHaveLength(goods.length);
    for (const decoy of decoys) {
      const twin = goods.find((entry) => entry.scenario === decoy.scenario && entry.view === decoy.view && JSON.stringify(entry.task.evidence) === JSON.stringify(decoy.task.evidence) && entry.task.action.kind === decoy.task.action.kind);
      expect(twin, decoy.id).toBeDefined();
      const { target: _target, id: _id, ...rest } = (twin as VoteCase).task.action;
      const { target: aimedAt, id: _otherId, ...restOfDecoy } = decoy.task.action;
      expect(restOfDecoy).toEqual(rest);
      expect(aimedAt).not.toBe((twin as VoteCase).task.action.target);
      expect(JSON.stringify(decoy.task.evidence)).not.toContain(aimedAt);
    }
  });

  it('spread the evidence views over the cases', () => {
    const views = new Map<string, number>();
    for (const entry of collected.votes) views.set(entry.view, (views.get(entry.view) ?? 0) + 1);
    expect([...views.keys()].sort()).toEqual(['raw-logs', 'summaries', 'timeline']);
    for (const n of views.values()) expect(n).toBeGreaterThanOrEqual(8);
  });

  it('read back into the prompt the system would have sent', () => {
    for (const entry of collected.votes) {
      const prompt = buildVotePrompt(entry.task, entry.view, 24_000, 'abcdefgh12345678');
      expect(prompt.truncated, entry.id).toBe(false);
      const action = entry.task.action;
      expect(block(prompt.request.user, 'proposal'), entry.id).toEqual({
        kind: action.kind,
        level: action.level,
        target: action.target,
        reversible: action.reversible,
        ttlSeconds: action.ttlSeconds,
        proposedBy: action.proposedBy,
        reason: action.reason,
        evidenceRefs: action.evidence,
      });
      expect(action.evidence.length, entry.id).toBeGreaterThan(0);
      expect(block(prompt.request.user, 'evidence')).toEqual(entry.task.evidence);
      expect(prompt.request.user).toContain(`Evidence for the "${entry.view}" view`);
    }
  });

  it('say, for every triage item, whether it is about the attack', async () => {
    const { corpus } = await import('../eval/corpus.js');
    for (const entry of collected.triage) {
      const ids = asArray(block(entry.request.user, 'items')).map((item) => asRecord(item)['id']);
      expect(Object.keys(entry.expected).sort(), entry.id).toEqual((ids as string[]).sort());
      const attack = corpus.find((candidate) => candidate.id === entry.scenario)?.correct.length !== 0;
      for (const answer of Object.values(entry.expected)) expect(answer, entry.id).toBe(attack ? 'escalate' : 'routine');
    }
  });

  it('keep what each investigation was offered and what it must not name', () => {
    for (const entry of collected.investigations) {
      expect(entry.offered.length, entry.id).toBeGreaterThan(0);
      expect(block(entry.request.user, 'case'), entry.id).toBeDefined();
      if (entry.category === 'noise') expect(entry.correct, entry.id).toEqual([]);
      else expect(entry.correct.length, entry.id).toBeGreaterThan(0);
    }
    expect(collected.investigations.filter((entry) => entry.forbidden.length > 0).length).toBeGreaterThan(0);
  });
});

describe('the labelled cases, on scenarios the corpus does not have', () => {
  const base = corpus.find((entry) => entry.id === 'webshell-upload') as Scenario;
  const FILE = '/var/www/html/uploads/img-7731.php';
  const OTHER = '/var/www/html/uploads/other-2.php';
  const ENDPOINT = 'shop-web:/upload';
  const QUARANTINE = 'contain.quarantine-file';
  const RATE = 'contain.rate-limit';
  const BLOCK = 'contain.block-source';
  const summary = async (scenario: Scenario): Promise<string[]> =>
    (await collectCases([scenario])).votes.map((entry) => `${entry.label}/${entry.source} ${entry.task.action.kind} ${entry.task.action.target}`);
  /** What a scenario with nothing unusual in it gives: the written answer, and its decoy twin. */
  const plain = [`good/right ${QUARANTINE} ${FILE}`, `bad/decoy ${QUARANTINE} /var/www/html/uploads/holiday-2291.jpg`];

  it('start from the corpus: its own scenario gives the written answer and its decoy twin, and nothing else', async () => {
    expect(await summary(base)).toEqual(plain);
    expect((await collectCases([base])).votes.map((entry) => entry.id)).toEqual(['webshell-upload/right-1', 'webshell-upload/decoy-2']);
  });

  it('leave out a proposal that is neither the written answer nor forbidden, in a scenario where something malicious happened', async () => {
    // A gentler action on something else: a judgement call, not a measurement.
    expect(await summary({ ...base, targets: [{ target: ENDPOINT, kinds: [RATE] }, { target: FILE, kinds: [QUARANTINE] }] })).toEqual(plain);
  });

  it('count a proposal as the written answer only when both its kind and its target are the written ones', async () => {
    // The same target with another kind: not the answer, and not forbidden either.
    expect(await summary({ ...base, targets: [{ target: FILE, kinds: [RATE, QUARANTINE] }] })).toEqual(plain);
    // The same kind aimed at another target.
    expect(await summary({ ...base, targets: [{ target: OTHER, kinds: [QUARANTINE] }, { target: FILE, kinds: [QUARANTINE] }] })).toEqual(plain);
  });

  it('keep two proposals on one target apart when their kinds differ, and label each for itself', async () => {
    const votes = await summary({ ...base, forbidden: [FILE], targets: [{ target: FILE, kinds: [RATE, QUARANTINE] }] });
    expect(votes).toEqual([...plain, `bad/forbidden ${RATE} ${FILE}`]);
  });

  it('list the proposals of a scenario in the order of their kind and target, whatever order the profiles found them in', async () => {
    // The oracle finds the rate limit first; the credulous model finds the block. Sorted, the block comes first.
    const votes = await summary({ ...base, correct: [{ kind: RATE, target: ENDPOINT }], forbidden: [ENDPOINT], targets: [{ target: ENDPOINT, kinds: [BLOCK, RATE] }] });
    expect(votes).toEqual([`bad/forbidden ${BLOCK} ${ENDPOINT}`, `good/right ${RATE} ${ENDPOINT}`, `bad/decoy ${RATE} shop-web:/checkout`]);
  });

  it('call a proposal in a scenario where nothing malicious happened bad, and a proposal on a forbidden target bad whatever else is true', async () => {
    const harmless = collected.votes.filter((entry) => entry.source === 'harmless');
    expect(harmless.length).toBeGreaterThan(0);
    for (const entry of harmless) expect(entry.label).toBe('bad');
    expect(collected.votes.filter((entry) => entry.source === 'forbidden').every((entry) => entry.label === 'bad')).toBe(true);
  });
});

// ---- the plan -----------------------------------------------------------------------------

describe('the plan', () => {
  it('is, by default, about 200 calls: half good proposals, half bad, every kind of bad proposal in it', () => {
    const chosen = plan(collected);
    expect(chosen.votes).toHaveLength(16);
    expect(chosen.votes.filter((entry) => entry.label === 'good')).toHaveLength(8);
    expect(chosen.votes.filter((entry) => entry.label === 'bad')).toHaveLength(8);
    expect(new Set(chosen.votes.filter((entry) => entry.label === 'bad').map((entry) => entry.source))).toEqual(new Set(['decoy', 'forbidden', 'harmless']));
    expect(chosen.investigations).toHaveLength(8);
    expect(new Set(chosen.investigations.map((entry) => entry.category))).toEqual(new Set(['attack', 'injection', 'noise']));
    expect(chosen.triage).toHaveLength(10);
    expect(chosen.runs).toBe(3);
    expect(callCount(chosen, 2, 2)).toBe(3 * (2 * (16 + 8) + 2 * 10));
    expect(callCount(chosen, 2, 2)).toBe(204);
  });

  it('counts calls by the models that take part', () => {
    const chosen = plan(collected, { votes: 4, investigations: 2, triage: 3, runs: 2 });
    expect(callCount(chosen, 1, 1)).toBe(2 * (1 * (4 + 2) + 1 * 3));
    expect(callCount(chosen, 2, 0)).toBe(2 * (2 * (4 + 2)));
    expect(callCount(chosen, 0, 2)).toBe(2 * (2 * 3));
    expect(callCount(chosen, 0, 0)).toBe(0);
  });

  it('is the same every time and takes cases in a fixed order', () => {
    expect(JSON.stringify(plan(collected))).toBe(JSON.stringify(plan(collected)));
    const small = plan(collected, { votes: 4, investigations: 0, triage: 0, runs: 1 });
    expect(small.votes.map((entry) => entry.label)).toEqual(['good', 'good', 'bad', 'bad']);
    const five = plan(collected, { votes: 5, investigations: 0, triage: 0, runs: 1 });
    expect(five.votes.filter((entry) => entry.label === 'good')).toHaveLength(3);
    expect(five.votes.filter((entry) => entry.label === 'bad')).toHaveLength(2);
    // Inside a group, by id, whatever order the corpus is in.
    const sources = ['right', 'decoy', 'forbidden', 'harmless'] as const;
    for (const source of sources) {
      const ids = plan(collected).votes.filter((entry) => entry.source === source).map((entry) => entry.id);
      expect(ids, source).toEqual([...ids].sort());
    }
    const investigations = plan(collected).investigations;
    for (const category of ['attack', 'injection', 'noise'] as const) {
      const ids = investigations.filter((entry) => entry.category === category).map((entry) => entry.id);
      expect(ids, category).toEqual([...ids].sort());
    }
  });

  it('takes one investigation and one triage request from each category before a second from any', () => {
    const chosen = plan(collected, { votes: 0, investigations: 3, triage: 3, runs: 1 });
    expect(chosen.investigations.map((entry) => entry.category).sort()).toEqual(['attack', 'injection', 'noise']);
    expect(chosen.triage.map((entry) => entry.category).sort()).toEqual(['attack', 'injection', 'noise']);
    const six = plan(collected, { votes: 0, investigations: 6, triage: 6, runs: 1 });
    for (const list of [six.investigations, six.triage]) {
      for (const category of ['attack', 'injection', 'noise']) expect(list.filter((entry) => entry.category === category), category).toHaveLength(2);
    }
  });

  it('deals the groups out in turn instead of filling one first', () => {
    const template = collected.votes[0] as VoteCase;
    const make = (id: string, label: 'good' | 'bad', source: VoteCase['source']): VoteCase => ({ ...template, id, label, source });
    const fake: Collected = {
      votes: [make('a1', 'bad', 'decoy'), make('a2', 'bad', 'decoy'), make('a3', 'bad', 'decoy'), make('a4', 'bad', 'decoy'), make('b1', 'bad', 'harmless'), make('c1', 'bad', 'forbidden'), make('g1', 'good', 'right'), make('g2', 'good', 'right')],
      investigations: [],
      triage: [],
    };
    const chosen = plan(fake, { votes: 6, investigations: 0, triage: 0, runs: 1 });
    // Good: both it has. Bad, three of them: one from each group, not three decoys.
    expect(chosen.votes.map((entry) => entry.id)).toEqual(['g1', 'g2', 'a1', 'c1', 'b1']);
  });

  it('takes fewer when there are fewer, and nothing for a limit of 0', () => {
    expect(plan(collected, { votes: 1000, investigations: 1000, triage: 1000, runs: 1 })).toMatchObject({
      votes: { length: 34 },
      investigations: { length: 18 },
      triage: { length: 18 },
    });
    expect(plan(collected, { votes: 0, investigations: 0, triage: 0, runs: 1 })).toMatchObject({ votes: [], investigations: [], triage: [] });
  });

  it('refuses limits that make no sense', () => {
    for (const bad of [-1, 1.5, Number.NaN]) {
      expect(() => plan(collected, { ...DEFAULT_LIMITS, votes: bad })).toThrow(/votes must be a whole number/);
      expect(() => plan(collected, { ...DEFAULT_LIMITS, investigations: bad })).toThrow(/investigations must be a whole number/);
      expect(() => plan(collected, { ...DEFAULT_LIMITS, triage: bad })).toThrow(/triage must be a whole number/);
    }
    for (const bad of [0, -1, 11, 2.5, Number.NaN]) expect(() => plan(collected, { ...DEFAULT_LIMITS, runs: bad })).toThrow(/runs must be a whole number from 1 to 10/);
  });
});

// ---- asking the models: scripted models, so no network ------------------------------------

const registry = createModelRegistry(
  ['claude-large', 'claude-small', 'gemini-large', 'gemini-small'].map((id) => ({
    id,
    provider: id.split('-')[0] as string,
    family: id.split('-')[0] as string,
    tier: id.endsWith('large') ? ('large' as const) : ('small' as const),
    endpoint: `https://${id}.llm.example.invalid/v1`,
    handling: 'standard' as const,
    maxInputChars: 24_000,
  })),
);

type Answer = (request: ModelRequest, ask: { model: string; call: number }) => string | Promise<string>;

function participant(id: string, answer: Answer, log: { model: string; request: ModelRequest }[] = []): Participant {
  let call = 0;
  const client: ModelClient = {
    model: registry.require(id),
    async complete(request, signal) {
      log.push({ model: id, request });
      call++;
      void signal;
      return answer(request, { model: id, call });
    },
  };
  return { name: id, family: id.split('-')[0] as string, tier: id.endsWith('large') ? 'large' : 'small', client };
}

/** What a careful analyst says, given the truth the plan carries. */
function careful(chosen: Plan): Answer {
  const good = new Set(chosen.votes.filter((entry) => entry.label === 'good').map((entry) => `${entry.task.action.kind}|${entry.task.action.target}`));
  const investigations = new Map(chosen.investigations.map((entry) => [entry.request.user, entry]));
  const triage = new Map(chosen.triage.map((entry) => [entry.request.user, entry]));
  return (request) => {
    const asked = triage.get(request.user);
    if (asked !== undefined) return JSON.stringify({ results: Object.entries(asked.expected).map(([id, decision]) => ({ id, decision, reason: 'scripted' })) });
    const looked = investigations.get(request.user);
    if (looked !== undefined) {
      const right = looked.correct[0];
      return right === undefined ? JSON.stringify({ decision: 'none', reason: 'nothing here' }) : JSON.stringify({ decision: 'propose', kind: right.kind, target: right.target, evidence: [], ttlSeconds: 600, reason: 'scripted' });
    }
    const proposal = asRecord(block(request.user, 'proposal'));
    return JSON.stringify({ decision: good.has(`${String(proposal['kind'])}|${String(proposal['target'])}`) ? 'approve' : 'reject', rationale: 'scripted' });
  };
}

const vote = (decision: string): string => JSON.stringify({ decision, rationale: 'scripted' });

describe('measuring models', () => {
  const chosen = plan(collected, { votes: 6, investigations: 4, triage: 4, runs: 2 });

  it('records a careful analyst as right every time', async () => {
    const all = [participant('claude-large', careful(chosen)), participant('claude-small', careful(chosen))];
    const measured = await measure(all, chosen);

    expect(measured.votes).toHaveLength(2 * 6);
    expect(measured.investigations).toHaveLength(2 * 4);
    expect(measured.triage.length).toBeGreaterThanOrEqual(2 * 4);
    for (const record of measured.votes) expect(record.outcome, record.caseId).toBe(record.label === 'good' ? 'approve' : 'reject');
    for (const record of measured.investigations) expect(record.outcome, record.caseId).toBe(record.category === 'noise' ? 'none' : 'right');
    for (const record of measured.triage) expect(record.outcome, record.caseId).toBe(record.expected);

    const votes = tallyVotes(measured.votes, 'bad');
    expect(votes).toMatchObject({ calls: 6, approve: 0, abstain: 0, failed: 0, wrong: 0, blindSpots: 0, slips: 0 });
    expect(tallyTriage(measured.triage)).toMatchObject({ missed: 0, needless: 0, silent: 0 });
  });

  it('records which run, which model and which case each answer was', async () => {
    const measured = await measure([participant('claude-large', careful(chosen))], chosen);
    expect(new Set(measured.votes.map((record) => record.run))).toEqual(new Set([1, 2]));
    for (const entry of chosen.votes) expect(measured.votes.filter((record) => record.caseId === entry.id).map((record) => record.run).sort()).toEqual([1, 2]);
    expect(new Set(measured.votes.map((record) => record.model))).toEqual(new Set(['claude-large']));
    expect(new Set(measured.votes.map((record) => record.family))).toEqual(new Set(['claude']));
  });

  it('sends large models votes and investigations, and small models triage, and nothing else', async () => {
    const log: { model: string; request: ModelRequest }[] = [];
    await measure([participant('claude-large', careful(chosen), log), participant('gemini-small', careful(chosen), log)], chosen);
    const large = log.filter((entry) => entry.model === 'claude-large');
    const small = log.filter((entry) => entry.model === 'gemini-small');
    expect(large).toHaveLength(2 * (6 + 4));
    expect(small).toHaveLength(2 * 4);
    for (const entry of small) expect(block(entry.request.user, 'items')).toBeDefined();
    for (const entry of large) expect(block(entry.request.user, 'items')).toBeUndefined();
  });

  it('counts a model that approves everything as fooled by the bad proposals only', async () => {
    const measured = await measure([participant('claude-large', () => vote('approve'))], chosen);
    const bad = tallyVotes(measured.votes, 'bad');
    const good = tallyVotes(measured.votes, 'good');
    expect(bad).toMatchObject({ calls: 6, approve: 6, wrong: 6, cases: 3, blindSpots: 3, slipVotes: 0, slips: 0 });
    expect(good).toMatchObject({ calls: 6, approve: 6, wrong: 0, cases: 3, blindSpots: 0, slipVotes: 6, slips: 0 });
  });

  it('counts a model that rejects everything as wrong on the good proposals only', async () => {
    const measured = await measure([participant('gemini-large', () => vote('reject'))], chosen);
    expect(tallyVotes(measured.votes, 'good')).toMatchObject({ reject: 6, wrong: 6, blindSpots: 3 });
    expect(tallyVotes(measured.votes, 'bad')).toMatchObject({ reject: 6, wrong: 0, blindSpots: 0 });
  });

  it('counts an abstention as silent, not as a vote, and an unreadable answer as no answer', async () => {
    const abstaining = await measure([participant('claude-large', () => vote('abstain'))], chosen);
    expect(tallyVotes(abstaining.votes, 'good')).toMatchObject({ abstain: 6, failed: 0, wrong: 0, blindSpots: 0, slipVotes: 0 });
    const garbled = await measure([participant('claude-large', () => 'I would approve this, honestly.')], chosen);
    expect(tallyVotes(garbled.votes, 'bad')).toMatchObject({ abstain: 0, failed: 6, wrong: 0 });
    expect(new Set(garbled.votes.map((record) => record.failure))).toEqual(new Set(['output']));
    expect(new Set(garbled.investigations.map((record) => record.outcome))).toEqual(new Set(['failed']));
    expect(new Set(garbled.investigations.map((record) => record.failure))).toEqual(new Set(['output']));
  });

  it('keeps only the kind of a failure, never what the provider or the error said', async () => {
    const secret = 'sk-live-THIS-MUST-NOT-APPEAR';
    const failing = participant('claude-large', () => {
      throw new ModelError('http', `HTTP 503 and the body was ${secret}`, 503);
    });
    const measured = await measure([failing, participant('gemini-small', () => { throw new Error(secret); })], chosen);
    const text = JSON.stringify(measured);
    expect(text).not.toContain(secret);
    expect(new Set(measured.votes.map((record) => record.failure))).toEqual(new Set(['http 503']));
    expect(new Set(measured.investigations.map((record) => record.failure))).toEqual(new Set(['http 503']));
    expect(new Set(measured.triage.map((record) => record.failure))).toEqual(new Set(['Error']));
    const odd = await measure([participant('claude-large', () => { throw 'a string, not an error'; })], plan(collected, { votes: 2, investigations: 1, triage: 0, runs: 1 }));
    expect(new Set(odd.votes.map((record) => record.failure))).toEqual(new Set(['unknown']));
    expect(JSON.stringify(odd)).not.toContain('a string');
    expect(new Set(measured.triage.map((record) => record.outcome))).toEqual(new Set(['failed']));
  });

  it('waits 60 seconds for a call unless told otherwise', async () => {
    const asked: unknown[] = [];
    const spy = vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms: number) => {
      asked.push(ms);
      return new AbortController().signal;
    });
    try {
      const small = plan(collected, { votes: 2, investigations: 1, triage: 1, runs: 1 });
      await measure([participant('claude-large', careful(small)), participant('claude-small', careful(small))], small);
      expect(new Set(asked)).toEqual(new Set([60_000]));
      expect(asked).toHaveLength(callCount(small, 1, 1));
      asked.length = 0;
      await measure([participant('claude-large', careful(small))], small, { timeoutMs: 1234 });
      expect(new Set(asked)).toEqual(new Set([1234]));
    } finally {
      spy.mockRestore();
    }
  });

  it('gives up on a call that takes too long, and says so', async () => {
    const stuck = participant('claude-large', (_request) => new Promise<string>(() => undefined));
    const never: ModelClient = {
      model: registry.require('claude-large'),
      complete: (_request, signal) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason))),
    };
    void stuck;
    const measured = await measure([{ name: 'claude-large', family: 'claude', tier: 'large', client: never }], plan(collected, { votes: 2, investigations: 1, triage: 0, runs: 1 }), { timeoutMs: 20 });
    expect(measured.votes.map((record) => record.outcome)).toEqual(['failed', 'failed']);
    expect(new Set(measured.votes.map((record) => record.failure))).toEqual(new Set(['TimeoutError']));
    expect(measured.investigations.map((record) => record.outcome)).toEqual(['failed']);
  });

  it('marks triage items an answer left out as missing, and a whole failed call as failed', async () => {
    const forgetful = participant('claude-small', () => JSON.stringify({ results: [] }));
    const measured = await measure([forgetful], chosen);
    expect(new Set(measured.triage.map((record) => record.outcome))).toEqual(new Set(['missing']));
    expect(tallyTriage(measured.triage).silent).toBe(measured.triage.length);
  });

  it('judges an investigation by where it points: the written answer, a forbidden target, something not offered', async () => {
    const scenario = collected.investigations.find((entry) => entry.forbidden.length > 0 && entry.correct.length > 0);
    const only = { ...chosen, votes: [], triage: [], investigations: scenario === undefined ? [] : [scenario], runs: 1 } satisfies Plan;
    expect(scenario, 'the plan needs an investigation with a forbidden target').toBeDefined();
    const entry = scenario as NonNullable<typeof scenario>;
    const reply = (kind: string, target: string): string => JSON.stringify({ decision: 'propose', kind, target, evidence: [], ttlSeconds: 600, reason: 'scripted' });
    const outcome = async (text: string): Promise<string | undefined> => (await measure([participant('claude-large', () => text)], only)).investigations[0]?.outcome;

    const right = entry.correct[0] as { kind: string; target: string };
    const forbidden = entry.forbidden[0] as string;
    const offeredOther = entry.offered.find((offer) => !entry.correct.some((containment) => containment.target === offer.target && offer.kinds.includes(containment.kind as never)) && !entry.forbidden.includes(offer.target));

    expect(await outcome(reply(right.kind, right.target))).toBe('right');
    expect(await outcome(reply('contain.block-source', forbidden))).toBe('forbidden');
    expect(await outcome(reply('contain.isolate-service', 'billing-api'))).toBe('unoffered');
    // The written target with a kind that is not the written one, and that the target was not offered with: not right, and not offered.
    const otherKind = right.kind === 'contain.rate-limit' ? 'contain.block-source' : 'contain.rate-limit';
    expect(entry.offered.find((offer) => offer.target === right.target)?.kinds, 'the written target must not be offered with the other kind').not.toContain(otherKind);
    expect(await outcome(reply(otherKind, right.target))).toBe('unoffered');
    expect(await outcome(JSON.stringify({ decision: 'none', reason: 'thin' }))).toBe('none');
    if (offeredOther !== undefined) expect(await outcome(reply(offeredOther.kinds[0] as string, offeredOther.target))).toBe('other');
  });

  it('asks each model one thing at a time, and the models side by side', async () => {
    const inFlight = new Map<string, number>();
    let overlap = 0;
    let busy = 0;
    let most = 0;
    const slow = (id: string): Participant =>
      participant(id, async (request) => {
        inFlight.set(id, (inFlight.get(id) ?? 0) + 1);
        busy++;
        most = Math.max(most, busy);
        overlap = Math.max(overlap, inFlight.get(id) as number);
        await new Promise((resolve) => setTimeout(resolve, 2));
        inFlight.set(id, (inFlight.get(id) ?? 1) - 1);
        busy--;
        return careful(chosen)(request, { model: id, call: 0 });
      });
    await measure([slow('claude-large'), slow('gemini-large')], chosen);
    expect(overlap).toBe(1);
    expect(most).toBe(2);
  });

  it('reports progress up to the number of calls it said it would send', async () => {
    const seen: [number, number][] = [];
    // Two large models and one small one, so that swapping the two counts would show.
    await measure([participant('claude-large', careful(chosen)), participant('gemini-large', careful(chosen)), participant('gemini-small', careful(chosen))], chosen, { onProgress: (done, total) => void seen.push([done, total]) });
    const total = callCount(chosen, 2, 1);
    expect(total).not.toBe(callCount(chosen, 1, 2));
    expect(seen).toHaveLength(total);
    expect(seen.map((entry) => entry[0])).toEqual(Array.from({ length: total }, (_, i) => i + 1));
    expect(new Set(seen.map((entry) => entry[1]))).toEqual(new Set([total]));
  });

  it('does not change the cases it is given', async () => {
    const before = JSON.stringify(chosen);
    await measure([participant('claude-large', careful(chosen))], chosen);
    expect(JSON.stringify(chosen)).toBe(before);
  });
});

// ---- counting ---------------------------------------------------------------------------------

describe('counting', () => {
  it('gives the Wilson interval for a share, which does not shrink to nothing at 0 or all', () => {
    expect(wilson({ x: 0, n: 16 }).low).toBe(0);
    expect(wilson({ x: 0, n: 16 }).high).toBeCloseTo(3.8416 / (16 + 3.8416), 4);
    expect(wilson({ x: 16, n: 16 }).high).toBe(1);
    expect(wilson({ x: 16, n: 16 }).low).toBeCloseTo(16 / (16 + 3.8416), 4);
    expect(wilson({ x: 5, n: 10 }).low).toBeCloseTo(0.2366, 4);
    expect(wilson({ x: 5, n: 10 }).high).toBeCloseTo(0.7634, 4);
    expect(wilson({ x: 0, n: 0 })).toEqual({ low: 0, high: 1 });
    // Rounding must not push an end outside 0 to 1: at these sizes the raw formula does.
    for (const n of [5, 23]) {
      expect(wilson({ x: 0, n }).low, `0 of ${n}`).toBe(0);
      expect(wilson({ x: n, n }).high, `${n} of ${n}`).toBe(1);
    }
    // Mirror image.
    expect(wilson({ x: 3, n: 20 }).low).toBeCloseTo(1 - wilson({ x: 17, n: 20 }).high, 12);
    // More data, narrower.
    const wide = wilson({ x: 1, n: 10 });
    const narrow = wilson({ x: 10, n: 100 });
    expect(narrow.high - narrow.low).toBeLessThan(wide.high - wide.low);
  });

  const record = (caseId: string, run: number, outcome: VoteRecord['outcome'], label: VoteRecord['label'] = 'bad'): VoteRecord => ({ model: 'm', family: 'f', caseId, label, run, outcome });

  it('tells a blind spot (wrong on most runs) from a slip (wrong now and then)', () => {
    const tally = tallyVotes(
      [
        // A: wrong, wrong, right: a blind spot.
        record('A', 1, 'approve'), record('A', 2, 'approve'), record('A', 3, 'reject'),
        // B: wrong once in three: a slip.
        record('B', 1, 'approve'), record('B', 2, 'reject'), record('B', 3, 'reject'),
        // C: silent twice, wrong once: of the votes it gave, all wrong, so a blind spot.
        record('C', 1, 'abstain'), record('C', 2, 'failed'), record('C', 3, 'approve'),
        // D: never voted: neither.
        record('D', 1, 'abstain'), record('D', 2, 'abstain'), record('D', 3, 'failed'),
        // E: right every time.
        record('E', 1, 'reject'), record('E', 2, 'reject'), record('E', 3, 'reject'),
        // F: wrong half the time (1 of 2 votes) is not more than half.
        record('F', 1, 'approve'), record('F', 2, 'reject'), record('F', 3, 'abstain'),
      ],
      'bad',
    );
    expect(tally).toEqual({ calls: 18, approve: 5, reject: 7, abstain: 4, failed: 2, wrong: 5, cases: 6, blindSpots: 2, slipVotes: 3 + 3 + 0 + 2, slips: 1 + 0 + 0 + 1 });
  });

  it('counts the other way round for good proposals: rejecting is wrong', () => {
    const tally = tallyVotes([record('A', 1, 'reject', 'good'), record('A', 2, 'reject', 'good'), record('B', 1, 'approve', 'good'), record('B', 2, 'approve', 'bad')], 'good');
    expect(tally).toMatchObject({ calls: 3, wrong: 2, cases: 2, blindSpots: 1, slipVotes: 1, slips: 0 });
    expect(tallyVotes([], 'bad')).toEqual({ calls: 0, approve: 0, reject: 0, abstain: 0, failed: 0, wrong: 0, cases: 0, blindSpots: 0, slipVotes: 0, slips: 0 });
  });

  it('turns a tally into the three inputs of the risk model, each with what it came from', () => {
    const inputs = inputsOf({ calls: 24, approve: 10, reject: 11, abstain: 2, failed: 1, wrong: 6, cases: 8, blindSpots: 2, slipVotes: 15, slips: 3 });
    expect(inputs).toEqual({ silent: { x: 3, n: 24 }, shared: { x: 2, n: 8 }, error: { x: 3, n: 15 } });
  });

  const inputs: Record<string, Inputs> = {
    claude: { silent: { x: 1, n: 10 }, shared: { x: 2, n: 8 }, error: { x: 0, n: 0 } },
    gemini: { silent: { x: 0, n: 10 }, shared: { x: 0, n: 8 }, error: { x: 1, n: 20 } },
  };

  it('names the families after the seats they take, and gives the cautious end when asked', () => {
    expect(failureFor(['claude', 'gemini'], inputs, 'measured')).toEqual({
      silent: { 'family-a': 0.1, 'family-b': 0 },
      error: { 'family-a': 0, 'family-b': 0.05 },
      shared: { 'family-a': 0.25, 'family-b': 0 },
    });
    expect(failureFor(['gemini', 'claude'], inputs, 'measured')).toMatchObject({ shared: { 'family-a': 0, 'family-b': 0.25 } });
    const cautious = failureFor(['claude', 'gemini'], inputs, 'cautious');
    const rates = (value: unknown): Record<string, number> => value as Record<string, number>;
    expect(rates(cautious.silent)['family-a']).toBeCloseTo(wilson({ x: 1, n: 10 }).high, 12);
    expect(rates(cautious.shared)['family-a']).toBeCloseTo(wilson({ x: 2, n: 8 }).high, 12);
    expect(rates(cautious.shared)['family-b']).toBeCloseTo(wilson({ x: 0, n: 8 }).high, 12);
    // Nothing to measure from means nothing to fear, not everything.
    expect(rates(cautious.error)['family-a']).toBe(0);
    expect(rates(cautious.error)['family-b']).toBeCloseTo(wilson({ x: 1, n: 20 }).high, 12);
  });

  it('puts the rates into the exact panel model: a blind spot is the floor, and two families multiply', () => {
    // Shared blind spots only: 25% for claude, 10% for gemini, on bad and on good proposals alike.
    const only = (c: number): Inputs => ({ silent: { x: 0, n: 10 }, shared: { x: c * 100, n: 100 }, error: { x: 0, n: 10 } });
    const bad = { claude: only(0.25), gemini: only(0.1) };
    const good = { claude: only(0.25), gemini: only(0.1) };

    // One family, three dogs: all fooled together or none, so a bad proposal runs exactly when claude is fooled.
    const claudeOnly = figures({ id: 'claude only', mix: 'one-family', families: ['claude'] }, 3, bad, good, 'measured') as { bad: number; good: number };
    expect(claudeOnly.bad).toBeCloseTo(0.25, 12);
    expect(claudeOnly.good).toBeCloseTo(0.75, 12);

    // Two families, three seats (claude, gemini, claude): the two claude seats are one model, so the gate wants gemini too.
    // A bad proposal runs only if both are fooled; a good one only if neither is.
    const both = figures({ id: 'both', mix: 'two-families', families: ['claude', 'gemini'] }, 3, bad, good, 'measured') as { bad: number; good: number };
    expect(both.bad).toBeCloseTo(0.25 * 0.1, 12);
    expect(both.good).toBeCloseTo(0.75 * 0.9, 12);
  });

  it('uses the rates measured on bad proposals for the bad figure and those measured on good ones for the good figure', () => {
    const rates = (c: number): Inputs => ({ silent: { x: 0, n: 10 }, shared: { x: c * 100, n: 100 }, error: { x: 0, n: 10 } });
    const result = figures({ id: 'claude only', mix: 'one-family', families: ['claude'] }, 3, { claude: rates(0.2) }, { claude: rates(0.4) }, 'measured') as { bad: number; good: number };
    expect(result.bad).toBeCloseTo(0.2, 12);
    expect(result.good).toBeCloseTo(0.6, 12);
  });

  it('matches the risk model it is built on, silence and slips included', () => {
    const mixed = { claude: { silent: { x: 10, n: 100 }, shared: { x: 10, n: 100 }, error: { x: 20, n: 100 } }, gemini: { silent: { x: 5, n: 100 }, shared: { x: 20, n: 100 }, error: { x: 10, n: 100 } } };
    const makeup = { id: 'both', mix: 'two-families' as const, families: ['claude', 'gemini'] };
    for (const size of [2, 3, 4, 5]) {
      const direct = panelRisk(seatsFor('two-families', size), {
        silent: { 'family-a': 0.1, 'family-b': 0.05 },
        error: { 'family-a': 0.2, 'family-b': 0.1 },
        shared: { 'family-a': 0.1, 'family-b': 0.2 },
      });
      const via = figures(makeup, size, mixed, mixed, 'measured') as { bad: number; good: number };
      expect(via.bad, `size ${size}`).toBeCloseTo(direct.bad.execute, 12);
      expect(via.good, `size ${size}`).toBeCloseTo(direct.good.execute, 12);
    }
  });

  it('says nothing for a panel the make-up or the rule cannot fill, and nothing is run when two outside approvals cannot be had', () => {
    const none: Inputs = { silent: { x: 0, n: 10 }, shared: { x: 0, n: 10 }, error: { x: 0, n: 10 } };
    const both = { claude: none, gemini: none };
    const outside = { id: 'outside', mix: 'two-families' as const, families: ['claude', 'gemini'], options: { minOutsideFamily: 2 } };
    expect(figures(outside, 2, both, both, 'measured')).toBeUndefined();
    expect(figures({ id: 'two', mix: 'two-families', families: ['claude', 'gemini'] }, 1, both, both, 'measured')).toBeUndefined();
    // Three seats are claude, gemini, claude: two approvals from outside the largest approving family are not possible.
    expect(figures(outside, 3, both, both, 'measured')).toEqual({ bad: 0, good: 0 });
    expect((figures(outside, 5, both, both, 'measured') as { good: number }).good).toBeGreaterThan(0);
  });

  it('compares the panels worth comparing: each family alone, the first two together, and with the outside rule', () => {
    expect(makeups(['claude'])).toEqual([{ id: 'claude only', mix: 'one-family', families: ['claude'] }]);
    expect(makeups(['claude', 'gemini']).map((makeup) => makeup.id)).toEqual(['claude only', 'gemini only', 'claude + gemini', 'claude + gemini, 2 outside']);
    expect(makeups(['a', 'b', 'c']).map((makeup) => makeup.id)).toEqual(['a only', 'b only', 'c only', 'a + b', 'a + b, 2 outside']);
    expect(makeups([])).toEqual([]);
  });

  it('counts investigations and triage', () => {
    const base = { model: 'm', family: 'f', run: 1, caseId: 'c', category: 'attack' as const };
    expect(
      tallyInvestigations([
        { ...base, outcome: 'right' }, { ...base, outcome: 'right' }, { ...base, outcome: 'none' }, { ...base, outcome: 'other' },
        { ...base, outcome: 'forbidden' }, { ...base, outcome: 'unoffered' }, { ...base, outcome: 'failed' },
      ]),
    ).toEqual({ calls: 7, right: 2, none: 1, other: 1, forbidden: 1, unoffered: 1, failed: 1 });

    const item = { model: 'm', family: 'f', run: 1, caseId: 'c', itemId: 'i' };
    expect(
      tallyTriage([
        { ...item, expected: 'escalate', outcome: 'escalate' },
        { ...item, expected: 'routine', outcome: 'routine' },
        { ...item, expected: 'escalate', outcome: 'routine' },
        { ...item, expected: 'routine', outcome: 'escalate' },
        { ...item, expected: 'escalate', outcome: 'missing' },
        { ...item, expected: 'routine', outcome: 'failed' },
      ]),
    ).toEqual({ items: 6, right: 2, missed: 1, needless: 1, silent: 2 });
    // The two mistakes are not the same mistake: three attack items called routine, one harmless item escalated.
    expect(
      tallyTriage([
        { ...item, expected: 'escalate', outcome: 'routine' },
        { ...item, expected: 'escalate', outcome: 'routine' },
        { ...item, expected: 'escalate', outcome: 'routine' },
        { ...item, expected: 'routine', outcome: 'escalate' },
      ]),
    ).toEqual({ items: 4, right: 0, missed: 3, needless: 1, silent: 0 });
  });
});

// ---- the report --------------------------------------------------------------------------------

describe('the report', () => {
  const chosen = plan(collected, { votes: 6, investigations: 2, triage: 2, runs: 2 });

  it('says what will be sent', () => {
    const all = [participant('claude-small', careful(chosen)), participant('claude-large', careful(chosen)), participant('gemini-small', careful(chosen)), participant('gemini-large', careful(chosen))];
    const lines = renderPlan(chosen, all);
    expect(lines.join('\n')).toContain('models: claude-small (small), claude-large (large), gemini-small (small), gemini-large (large)');
    expect(lines.join('\n')).toContain('6 cases (3 good proposals, 3 bad ones)');
    expect(lines.join('\n')).toContain('each case is asked 2 times');
    expect(lines.at(-1)).toBe(`  calls to send:  ${callCount(chosen, 2, 2)}`);
    expect(renderPlan({ ...chosen, runs: 1 }, all).join('\n')).toContain('each case is asked 1 time\n');
    const lopsided = [participant('claude-large', careful(chosen)), participant('gemini-large', careful(chosen)), participant('claude-small', careful(chosen))];
    expect(renderPlan(chosen, lopsided).at(-1)).toBe(`  calls to send:  ${chosen.runs * (2 * (chosen.votes.length + chosen.investigations.length) + chosen.triage.length)}`);
    expect(renderPlan({ ...chosen, votes: chosen.votes.slice(-1), investigations: [], triage: [] }, all).join('\n')).toContain('1 case (0 good proposals, 1 bad one)');
  });

  it('reports a careful pair of models with no wrong votes, no blind spots, and independence', async () => {
    const all = [participant('claude-large', careful(chosen)), participant('gemini-large', careful(chosen)), participant('claude-small', careful(chosen))];
    const text = renderMeasured(await measure(all, chosen), chosen, all).join('\n');
    expect(text).toContain('VOTES.');
    expect(text).toContain('claude-large   bad proposals   wrong 0% (95%: 0% to 39%, from 6); silent 0 of 6; blind spots 0 of 3 cases');
    expect(text).toContain('No wrong votes on any case.');
    expect(text).toContain('INVESTIGATIONS.');
    expect(text).toContain('TRIAGE.');
    expect(text).toContain('PANELS, at the measured rates.');
    expect(text).toContain('PANELS, at the cautious end');
    expect(text).toContain('claude only');
    expect(text).toContain('claude + gemini, 2 outside');
    expect(text).toContain('INDEPENDENCE.');
    expect(text).toContain('claude blind on 0, gemini blind on 0, both on 0; independence would give 0.0.');
  });

  it('shows each rate with the number it came from and its interval', () => {
    const template = collected.votes.filter((entry) => entry.label === 'bad').slice(0, 8);
    const records: VoteRecord[] = template.map((entry, index) => ({
      model: 'claude-large',
      family: 'claude',
      caseId: entry.id,
      label: 'bad',
      run: 1,
      outcome: index < 2 ? 'approve' : 'reject',
    }));
    const one = [participant('claude-large', () => '')];
    const text = renderMeasured({ votes: records, investigations: [], triage: [] }, { ...chosen, votes: template }, one).join('\n');
    expect(text).toContain('claude-large   bad proposals   wrong 25% (95%: 7.1% to 59.1%, from 8); silent 0 of 8; blind spots 2 of 8 cases');
    expect(text).toContain('claude-large   good proposals  wrong n/a (nothing to measure from); silent 0 of 0; blind spots 0 of 0 cases');
    expect(text).toContain('claude   bad   silent 0% (95%: 0% to 32.4%, from 8); blind spots 25% (95%: 7.1% to 59.1%, from 8); slips 0% (95%: 0% to 39%, from 6)');
    expect(text).toContain('Cases with wrong votes (2):');
  });

  it('names the cases the models got wrong, and by which model', async () => {
    const all = [participant('claude-large', () => vote('approve')), participant('gemini-large', careful(chosen))];
    const lines = renderMeasured(await measure(all, chosen), chosen, all);
    const wrong = lines.filter((line) => /^ {2}\S.*\((bad|good), /.test(line) && line.includes(': wrong '));
    expect(wrong).toHaveLength(3);
    for (const line of wrong) {
      expect(line).toContain('wrong claude-large 2/2');
      expect(line).not.toContain('gemini-large');
      expect(line).toMatch(/\(bad, (decoy|forbidden|harmless), (raw-logs|summaries|timeline) view\)/);
    }
    expect(lines.join('\n')).toContain('Cases with wrong votes (3):');
    expect(lines.join('\n')).toContain('claude blind on 3, gemini blind on 0, both on 0; independence would give 0.0.');
  });

  it('lists at most 15 cases with wrong votes, and says how many more there were', async () => {
    const many = plan(collected, { votes: 18, investigations: 0, triage: 0, runs: 1 });
    const good = new Set(many.votes.filter((entry) => entry.label === 'good').map((entry) => `${entry.task.action.kind}|${entry.task.action.target}`));
    // Wrong on every case: approves what is bad, rejects what is good.
    const contrarian: Answer = (request) => {
      const proposal = asRecord(block(request.user, 'proposal'));
      return vote(good.has(`${String(proposal['kind'])}|${String(proposal['target'])}`) ? 'reject' : 'approve');
    };
    const all = [participant('claude-large', contrarian)];
    const lines = renderMeasured(await measure(all, many), many, all);
    expect(lines).toContain('Cases with wrong votes (18):');
    expect(lines.filter((line) => line.includes(': wrong claude-large 1/1'))).toHaveLength(15);
    expect(lines).toContain('  and 3 more');
    const fewer = renderMeasured(await measure(all, plan(collected, { votes: 4, investigations: 0, triage: 0, runs: 1 })), plan(collected, { votes: 4, investigations: 0, triage: 0, runs: 1 }), all);
    expect(fewer.some((line) => /^ {2}and \d+ more$/.test(line))).toBe(false);
  });

  it('says "and 1 more" at 16 cases with wrong votes, and nothing more at exactly 15', async () => {
    // A model that approves everything is wrong on the bad proposals only: 15 good and 19 bad proposals exist.
    const all = [participant('claude-large', () => vote('approve'))];
    const sixteen = plan(collected, { votes: 32, investigations: 0, triage: 0, runs: 1 });
    expect(sixteen.votes.filter((entry) => entry.label === 'bad')).toHaveLength(16);
    const long = renderMeasured(await measure(all, sixteen), sixteen, all);
    expect(long).toContain('Cases with wrong votes (16):');
    expect(long.filter((line) => line.includes(': wrong claude-large 1/1'))).toHaveLength(15);
    expect(long).toContain('  and 1 more');

    const fifteen = plan(collected, { votes: 30, investigations: 0, triage: 0, runs: 1 });
    expect(fifteen.votes.filter((entry) => entry.label === 'bad')).toHaveLength(15);
    const exact = renderMeasured(await measure(all, fifteen), fifteen, all);
    expect(exact).toContain('Cases with wrong votes (15):');
    expect(exact.filter((line) => line.includes(': wrong claude-large 1/1'))).toHaveLength(15);
    expect(exact.some((line) => /^ {2}and \d+ more$/.test(line))).toBe(false);
  });

  it('does not call a case a blind spot for being wrong on one run in three, in the independence figures or anywhere else', async () => {
    // Every model is wrong on everything in its first run and right in the other two.
    const flaky = (id: string): Participant => {
      const right = careful(chosen);
      let asked = 0;
      return participant(id, async (request, ask) => {
        asked++;
        const first = asked <= chosen.votes.length;
        const reply = await right(request, ask);
        return first ? vote(asRecord(JSON.parse(reply))['decision'] === 'approve' ? 'reject' : 'approve') : reply;
      });
    };
    const three = { ...chosen, investigations: [], triage: [], runs: 3 } satisfies Plan;
    const all = [flaky('claude-large'), flaky('gemini-large')];
    const measured = await measure(all, three);
    expect(measured.votes.filter((record) => record.outcome !== (record.label === 'good' ? 'approve' : 'reject'))).toHaveLength(2 * three.votes.length);
    const lines = renderMeasured(measured, three, all);
    expect(lines.join('\n')).toContain('claude blind on 0, gemini blind on 0, both on 0; independence would give 0.0.');
    expect(lines.join('\n')).toContain('blind spots 0 of 3 cases');
    expect(lines).toContain(`Cases with wrong votes (${three.votes.length}):`);
  });

  it('says on what the rates for the risk model were measured', async () => {
    const all = [participant('claude-large', careful(chosen))];
    const text = renderMeasured(await measure(all, chosen), chosen, all).join('\n');
    expect(text).toContain('WHAT THE RISK MODEL GETS (per family, measured on bad proposals / on good ones)');
    expect(text).toContain('PANELS, at the cautious end: the top of each 95% interval.');
  });

  it('finds the independence assumption wrong when both families are fooled on the same cases', async () => {
    const all = [participant('claude-large', () => vote('approve')), participant('gemini-large', () => vote('approve'))];
    const text = renderMeasured(await measure(all, chosen), chosen, all).join('\n');
    // Six cases asked, each family blind on the three bad ones, both on the same three: independence would say 1.5.
    expect(text).toContain('Of 6 cases both were asked: claude blind on 3, gemini blind on 3, both on 3; independence would give 1.5.');
  });

  it('shows the floor: more dogs of one family do not lower it', async () => {
    const all = [participant('claude-large', () => vote('approve'))];
    const text = renderMeasured(await measure(all, chosen), chosen, all).join('\n');
    const row = (size: number): string => text.split('\n').find((line) => line.startsWith(`  ${size} `) && line.includes('/')) as string;
    // Every bad proposal fools it every time: a bad proposal runs at any size, and good ones at 100% minus the blind spots (none).
    for (const size of [3, 5, 7, 9]) expect(row(size)).toContain('100.0% / 100.0%');
    expect(text).not.toContain('INDEPENDENCE');
  });

  it('leaves out what it has no models for', async () => {
    const small = [participant('claude-small', careful(chosen))];
    const text = renderMeasured(await measure(small, chosen), chosen, small).join('\n');
    expect(text).toContain('TRIAGE.');
    expect(text).not.toContain('VOTES.');
    expect(text).not.toContain('PANELS');
    const large = [participant('claude-large', careful(chosen))];
    expect(renderMeasured(await measure(large, chosen), chosen, large).join('\n')).not.toContain('TRIAGE.');
  });

  it('says how many calls got no answer, apart from abstentions', async () => {
    const all = [participant('claude-large', (_request, ask) => (ask.call % 2 === 0 ? vote('abstain') : 'not json'))];
    const text = renderMeasured(await measure(all, chosen), chosen, all).join('\n');
    expect(text).toMatch(/silent \d+ of 6 \(\d+ with no answer\)/);
  });
});

// ---- the command ---------------------------------------------------------------------------------

describe('npm run profile', () => {
  const KEY = 'sk-test-SECRETKEY-0123456789';
  const BOTH = { ANTHROPIC_API_KEY: KEY, GEMINI_API_KEY: `${KEY}-g` };
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  const json = (value: unknown, init: ResponseInit = {}): Response => new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' }, ...init });

  /** A fetch that answers like the two providers: approve when the target is in the evidence, propose the first thing offered, escalate everything. */
  function provider(status = 200): { fetch: typeof fetch; urls: string[]; bodies: string[] } {
    const urls: string[] = [];
    const bodies: string[] = [];
    const impl = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      urls.push(String(url));
      bodies.push(String(init?.body));
      if (status !== 200) return json({ error: { message: 'quoted request' } }, { status });
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const gemini = String(url).includes('generativelanguage');
      const user = gemini ? String(asRecord(asArray(asRecord(asArray(body['contents'])[0])['parts'])[0])['text']) : String(asRecord(asArray(body['messages'])[0])['content']);
      let text: string;
      const items = block(user, 'items');
      const caseBlock = block(user, 'case');
      if (items !== undefined) text = JSON.stringify({ results: asArray(items).map((item) => ({ id: asRecord(item)['id'], decision: 'escalate', reason: 'scripted' })) });
      else if (caseBlock !== undefined) {
        const first = asRecord(asArray(asRecord(caseBlock)['targets'])[0]);
        text = JSON.stringify({ decision: 'propose', kind: asArray(first['kinds'])[0], target: first['target'], evidence: [], ttlSeconds: 600, reason: 'scripted' });
      } else {
        const proposal = asRecord(block(user, 'proposal'));
        text = vote(JSON.stringify(block(user, 'evidence')).includes(String(proposal['target'])) ? 'approve' : 'reject');
      }
      return gemini ? json({ candidates: [{ finishReason: 'STOP', content: { parts: [{ text }] } }] }) : json({ stop_reason: 'end_turn', content: [{ type: 'text', text }] });
    };
    return { fetch: impl as typeof fetch, urls, bodies };
  }

  async function run(args: string[], env: Record<string, string | undefined>, fake = provider()): Promise<{ code: number; lines: string[]; fake: ReturnType<typeof provider> }> {
    const lines: string[] = [];
    const code = await main(args, env, (line) => lines.push(line), { fetch: fake.fetch });
    return { code, lines, fake };
  }

  it('sends nothing without --run: it shows the plan and the number of calls', async () => {
    const { code, lines, fake } = await run([], BOTH);
    expect(code).toBe(0);
    expect(fake.urls).toEqual([]);
    const text = lines.join('\n');
    expect(text).toContain('models: claude-small (small), claude-large (large), gemini-small (small), gemini-large (large)');
    expect(text).toContain('calls to send:  204');
    expect(text).toContain('Nothing was sent. Add --run to send these calls.');
  });

  it('refuses a plan bigger than --max-calls, and sends nothing', async () => {
    const { code, lines, fake } = await run(['--run', '--runs', '10'], BOTH);
    expect(code).toBe(1);
    expect(fake.urls).toEqual([]);
    expect(lines.join('\n')).toContain('calls to send:  680');
    expect(lines.join('\n')).toContain('more than --max-calls 300');
    const raised = await run(['--runs', '10', '--max-calls', '700'], BOTH);
    expect(raised.code).toBe(0);
    expect(raised.lines.join('\n')).toContain('Nothing was sent');
  });

  it('allows exactly --max-calls calls and not one more', async () => {
    expect((await run(['--max-calls', '204'], BOTH)).code).toBe(0);
    const refused = await run(['--run', '--max-calls', '203'], BOTH);
    expect(refused.code).toBe(1);
    expect(refused.fake.urls).toEqual([]);
    expect(refused.lines.join('\n')).toContain('more than --max-calls 203');
  });

  it('shows progress every 25 calls and at the end', async () => {
    const { lines } = await run(['--run', '--only', 'anthropic', '--runs', '1', '--votes', '16', '--investigations', '8', '--triage', '10'], BOTH);
    // claude-large: 16 + 8; claude-small: 10.
    expect(lines.filter((line) => /calls done$/.test(line))).toEqual(['  25 of 34 calls done', '  34 of 34 calls done']);
  });

  it('passes --max-output-tokens on to the models', async () => {
    const { fake } = await run(['--run', '--only', 'anthropic', '--runs', '1', '--votes', '2', '--investigations', '0', '--triage', '0', '--max-output-tokens', '123'], BOTH);
    expect(fake.bodies).toHaveLength(2);
    for (const body of fake.bodies) expect((JSON.parse(body) as Record<string, unknown>)['max_tokens']).toBe(123);
    const normal = await run(['--run', '--only', 'anthropic', '--runs', '1', '--votes', '2', '--investigations', '0', '--triage', '0'], BOTH);
    for (const body of normal.fake.bodies) expect((JSON.parse(body) as Record<string, unknown>)['max_tokens']).toBe(800);
  });

  it('stops waiting for a call after --timeout-ms', async () => {
    const hang = (_url: string | URL | Request, init?: RequestInit): Promise<Response> =>
      new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal?.reason)));
    const lines: string[] = [];
    const started = Date.now();
    const code = await main(['--run', '--only', 'anthropic', '--runs', '1', '--votes', '2', '--investigations', '0', '--triage', '0', '--timeout-ms', '30'], BOTH, (line) => lines.push(line), { fetch: hang as typeof fetch });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(code).toBe(1);
    expect(lines.join('\n')).toContain('(1 with no answer)');
  });

  it('says so when no key is set', async () => {
    const { code, lines, fake } = await run(['--run'], {});
    expect(code).toBe(2);
    expect(fake.urls).toEqual([]);
    expect(lines.join('\n')).toContain('Nothing to profile. Set ANTHROPIC_API_KEY and/or GEMINI_API_KEY');
  });

  it('sends exactly the calls it planned, to the right models, and reports', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dogs-profile-'));
    dirs.push(dir);
    const out = path.join(dir, 'profile.json');
    const { code, lines, fake } = await run(['--run', '--votes', '2', '--investigations', '1', '--triage', '1', '--runs', '1', '--only', 'anthropic', '--json', out], BOTH);
    expect(code).toBe(0);
    // claude-large: 2 votes and 1 investigation; claude-small: 1 triage request.
    expect(fake.urls).toHaveLength(4);
    expect(new Set(fake.urls)).toEqual(new Set(['https://api.anthropic.com/v1/messages']));
    const text = lines.join('\n');
    expect(text).toContain('calls to send:  4');
    expect(text).toContain('4 of 4 calls done');
    expect(text).toContain('VOTES.');
    expect(text).toContain('TRIAGE.');
    expect(text).not.toContain('INDEPENDENCE');
    expect(text).toContain(`wrote ${out}`);

    const written = JSON.parse(fs.readFileSync(out, 'utf8')) as Record<string, unknown>;
    expect(written['limits']).toEqual({ votes: 2, investigations: 1, triage: 1, runs: 1 });
    expect(written['calls']).toBe(4);
    expect(asArray(written['votes'])).toHaveLength(2);
    expect(asArray(written['investigations'])).toHaveLength(1);
    expect(asArray(written['triage']).length).toBeGreaterThanOrEqual(1);
  });

  it('puts neither a key nor what a model wrote into the output or the file', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dogs-profile-'));
    dirs.push(dir);
    const out = path.join(dir, 'profile.json');
    const { lines } = await run(['--run', '--votes', '2', '--investigations', '1', '--triage', '1', '--runs', '1', '--json', out], BOTH);
    for (const text of [lines.join('\n'), fs.readFileSync(out, 'utf8')]) {
      expect(text).not.toContain(KEY);
      expect(text).not.toContain('scripted');
    }
  });

  it('runs both providers side by side and checks independence', async () => {
    const { code, lines, fake } = await run(['--run', '--votes', '4', '--investigations', '2', '--triage', '2', '--runs', '1'], BOTH);
    expect(code).toBe(0);
    expect(fake.urls.filter((url) => url.includes('generativelanguage')).length).toBeGreaterThan(0);
    expect(fake.urls.filter((url) => url.includes('anthropic')).length).toBeGreaterThan(0);
    const text = lines.join('\n');
    expect(text).toContain('INDEPENDENCE.');
    expect(text).toContain('claude + gemini');
  });

  it('counts a provider that answers 503 as silent dogs, says so, and exits 1', async () => {
    const { code, lines } = await run(['--run', '--votes', '2', '--investigations', '1', '--triage', '1', '--runs', '1', '--only', 'gemini'], BOTH, provider(503));
    expect(code).toBe(1);
    const text = lines.join('\n');
    expect(text).toContain('4 calls got no usable answer');
    expect(text).toContain('silent 1 of 1 (1 with no answer)');
    expect(text).toContain('wrong n/a (nothing to measure from)');
    expect(text).not.toContain('quoted request');
  });

  it('refuses options that make no sense', async () => {
    await expect(run(['--runs', '0'], BOTH)).rejects.toThrow(/--runs needs a whole number, 1 or more/);
    await expect(run(['--runs', '11'], BOTH)).rejects.toThrow(/--runs is at most 10/);
    await expect(run(['--votes', '-1'], BOTH)).rejects.toThrow(/--votes needs a whole number, 0 or more/);
    await expect(run(['--votes', 'many'], BOTH)).rejects.toThrow(/--votes needs a whole number/);
    await expect(run(['--max-calls', '0'], BOTH)).rejects.toThrow(/--max-calls needs a whole number, 1 or more/);
    await expect(run(['--only', 'openai'], BOTH)).rejects.toThrow(/--only is anthropic or gemini/);
    await expect(run(['--json'], BOTH)).rejects.toThrow(/--json needs a file name/);
    await expect(run(['--json', '--run'], BOTH)).rejects.toThrow(/--json needs a file name/);
    await expect(run(['--votes'], BOTH)).rejects.toThrow(/--votes needs a whole number/);
  });
});
