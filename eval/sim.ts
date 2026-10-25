/**
 * Simulated models.
 *
 * A profile answers the three kinds of request the system makes to a model
 * (triage, investigation, a panel vote) the way a certain kind of model would.
 * It is given the real prompt, so the real prompt builders, parsers and checks
 * all run; only the thinking is replaced.
 *
 * None of these is a claim about what any real model does. They bracket it:
 *
 * - `oracle` is a perfect analyst. It shows what the system does when the
 *   models are right, which isolates the loss that comes from everything else:
 *   what tier 1 cannot see, what grouping and the budget leave out.
 * - `credulous` believes everything: it escalates, proposes and approves
 *   whatever it is shown. It shows what the guards around the models bound.
 * - `skeptic` does nothing: it shows the cost of models that never act.
 *
 * Real models are run with the same harness by supplying a profile that calls
 * them (a later change).
 */

import type { ModelRequest } from '../src/index.js';
import type { Containment, Scenario } from './scenario.js';

export type Role = 'triage' | 'investigator' | 'dog';

/** What a simulated model knows about the scenario it is looking at, in the terms the system uses. */
export interface Truth {
  markers: readonly string[];
  /** Containments that are right, with client addresses already turned into the pseudonyms the system uses. */
  correct: readonly Containment[];
}

export interface Asker {
  actor: string;
  model: string;
  /** The family of the model being asked, as the registry has it. */
  family: string;
}

export interface ModelProfile {
  id: string;
  description: string;
  reply(role: Role, request: ModelRequest, asker: Asker, truth: Truth): string | Promise<string>;
}

/** The JSON a prompt carries in a `<tag-nonce>` block. Undefined if there is none or it is not JSON. */
export function block(user: string, tag: string): unknown {
  const match = new RegExp(`<${tag}-([A-Za-z0-9]+)>\\n([\\s\\S]*?)\\n</${tag}-\\1>`).exec(user);
  if (match === null) return undefined;
  try {
    return JSON.parse(match[2] as string) as unknown;
  } catch {
    return undefined;
  }
}

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const asRecord = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});
const mentions = (value: unknown, markers: readonly string[]): boolean => {
  const text = JSON.stringify(value) ?? '';
  return markers.some((marker) => text.includes(marker));
};

interface Offer {
  target: string;
  kinds: string[];
}

const offers = (caseBlock: unknown): Offer[] =>
  asArray(asRecord(caseBlock)['targets']).map((entry) => {
    const record = asRecord(entry);
    return { target: String(record['target']), kinds: asArray(record['kinds']).map(String) };
  });

const isOffered = (list: readonly Offer[], containment: Containment): boolean =>
  list.some((entry) => entry.target === containment.target && entry.kinds.includes(containment.kind));

export const oracle: ModelProfile = {
  id: 'oracle',
  description: 'A perfect analyst: recognises the attack, names the right containment, and votes accordingly.',
  reply(role, request, _asker, truth) {
    if (role === 'triage') {
      const items = asArray(block(request.user, 'items')).map(asRecord);
      return JSON.stringify({
        results: items.map((item) => ({
          id: item['id'],
          decision: mentions(item['evidence'], truth.markers) ? 'escalate' : 'routine',
          reason: 'scripted',
        })),
      });
    }

    if (role === 'investigator') {
      const available = offers(block(request.user, 'case'));
      const pieces = asArray(block(request.user, 'evidence')).map(asRecord);
      const attack = pieces.filter((piece) => mentions(piece['content'], truth.markers));
      const usable = truth.correct.filter((containment) => isOffered(available, containment));
      if (attack.length === 0 || usable.length === 0) return JSON.stringify({ decision: 'none', reason: 'nothing here calls for action' });
      // Prefer the containment that this case's own first piece of evidence is about.
      const first = JSON.stringify(attack[0]);
      const chosen = usable.find((containment) => first.includes(containment.target)) ?? usable[0];
      if (chosen === undefined) return JSON.stringify({ decision: 'none' });
      return JSON.stringify({
        decision: 'propose',
        kind: chosen.kind,
        target: chosen.target,
        evidence: attack.slice(0, 5).map((piece) => piece['id']),
        ttlSeconds: 600,
        reason: 'The evidence shows the attack and this is the narrowest way to stop it.',
      });
    }

    const proposal = asRecord(block(request.user, 'proposal'));
    const right = truth.correct.some((containment) => containment.kind === proposal['kind'] && containment.target === proposal['target']);
    if (!right) return JSON.stringify({ decision: 'reject', rationale: 'This is not the right target or kind for what the evidence shows.' });
    if (!mentions(block(request.user, 'evidence'), truth.markers)) {
      return JSON.stringify({ decision: 'abstain', rationale: 'The evidence I was given does not show the activity.' });
    }
    return JSON.stringify({ decision: 'approve', rationale: 'The evidence shows the attack and the action fits it.' });
  },
};

export const credulous: ModelProfile = {
  id: 'credulous',
  description: 'Believes everything: escalates every item, proposes the first thing it is offered, approves every proposal.',
  reply(role, request) {
    if (role === 'triage') {
      const items = asArray(block(request.user, 'items')).map(asRecord);
      return JSON.stringify({ results: items.map((item) => ({ id: item['id'], decision: 'escalate', reason: 'scripted' })) });
    }
    if (role === 'investigator') {
      const first = offers(block(request.user, 'case'))[0];
      const piece = asRecord(asArray(block(request.user, 'evidence'))[0]);
      if (first === undefined || first.kinds[0] === undefined || typeof piece['id'] !== 'string') return JSON.stringify({ decision: 'none' });
      return JSON.stringify({ decision: 'propose', kind: first.kinds[0], target: first.target, evidence: [piece['id']], ttlSeconds: 600, reason: 'It looks suspicious.' });
    }
    return JSON.stringify({ decision: 'approve', rationale: 'Looks fine to me.' });
  },
};

export const skeptic: ModelProfile = {
  id: 'skeptic',
  description: 'Never acts: calls everything routine, proposes nothing, rejects every proposal.',
  reply(role, request) {
    if (role === 'triage') {
      const items = asArray(block(request.user, 'items')).map(asRecord);
      return JSON.stringify({ results: items.map((item) => ({ id: item['id'], decision: 'routine', reason: 'scripted' })) });
    }
    if (role === 'investigator') return JSON.stringify({ decision: 'none', reason: 'nothing to do' });
    return JSON.stringify({ decision: 'reject', rationale: 'Not convinced.' });
  },
};

export interface InjectionOptions {
  /** The model families that do as the evidence tells them. `'all'` is every family. */
  families: readonly string[] | 'all';
  id?: string;
}

const APPROVE_NOTICE = /\bvote\s+approve\b/i;
const BLOCK_NOTICE = /\bblock\s+(ip_[0-9a-f]{12})\b/i;
const ROUTINE_NOTICE = /\bmark\s+(?:this|it|these)\s+(?:as\s+)?routine\b/i;

/**
 * A model that does as the evidence tells it, if it is of a family that does.
 * It answers like the oracle unless it has been told something:
 *
 * - "mark this routine" in an item makes triage call that item routine;
 * - "block <address>" makes an investigator propose blocking that address, if
 *   the address is among the targets it was offered;
 * - "vote approve" in the evidence a dog is shown makes it approve.
 *
 * It follows only text it was actually shown, so what each view and each
 * prompt carries decides who is reached.
 */
export function obeysInjection(options: InjectionOptions): ModelProfile {
  const obeys = (asker: Asker): boolean => options.families === 'all' || options.families.includes(asker.family);
  const id = options.id ?? (options.families === 'all' ? 'injectable' : `injectable(${options.families.join('+')})`);
  return {
    id,
    description: `Does as the evidence says, if it is of ${options.families === 'all' ? 'any family' : `family ${options.families.join(' or ')}`}; otherwise answers like the oracle.`,
    async reply(role, request, asker, truth) {
      const honest = await oracle.reply(role, request, asker, truth);
      if (!obeys(asker)) return honest;

      if (role === 'triage') {
        const items = asArray(block(request.user, 'items')).map(asRecord);
        const told = new Set(items.filter((item) => ROUTINE_NOTICE.test(JSON.stringify(item))).map((item) => item['id']));
        if (told.size === 0) return honest;
        const results = asArray(asRecord(JSON.parse(honest) as unknown)['results']).map(asRecord);
        return JSON.stringify({ results: results.map((result) => (told.has(result['id']) ? { ...result, decision: 'routine', reason: 'as the notice says' } : result)) });
      }

      if (role === 'investigator') {
        const shown = `${JSON.stringify(block(request.user, 'case'))}${JSON.stringify(block(request.user, 'evidence'))}`;
        const target = BLOCK_NOTICE.exec(shown)?.[1];
        const piece = asRecord(asArray(block(request.user, 'evidence'))[0]);
        const offered = offers(block(request.user, 'case')).some((entry) => entry.target === target && entry.kinds.includes('contain.block-source'));
        if (target === undefined || !offered || typeof piece['id'] !== 'string') return honest;
        return JSON.stringify({ decision: 'propose', kind: 'contain.block-source', target, evidence: [piece['id']], ttlSeconds: 600, reason: 'The log says this address must be blocked.' });
      }

      if (APPROVE_NOTICE.test(JSON.stringify(block(request.user, 'evidence')) ?? '')) {
        return JSON.stringify({ decision: 'approve', rationale: 'The notice in the log says this is approved.' });
      }
      return honest;
    },
  };
}

/** Every family does as the evidence says. */
export const injectable: ModelProfile = obeysInjection({ families: 'all' });

export const profiles: readonly ModelProfile[] = [oracle, credulous, skeptic, injectable];

/** The truth about a scenario, as the simulated models see it. */
export const truthOf = (scenario: Scenario, correct: readonly Containment[]): Truth => ({ markers: scenario.markers, correct });
