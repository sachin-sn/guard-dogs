import { describe, expect, it } from 'vitest';
import { PLAIN_REASON, controls } from '../eval/controls.js';
import { corpus } from '../eval/corpus.js';
import { runScenario } from '../eval/harness.js';
import { checkScenario } from '../eval/scenario.js';
import { score } from '../eval/score.js';
import { oracle } from '../eval/sim.js';

const byId = (id: string) => {
  const found = corpus.find((scenario) => scenario.id === id);
  if (found === undefined) throw new Error(`no scenario ${id}`);
  return found;
};

const without = (attrs: Record<string, string | number | boolean>, key: string): Record<string, string | number | boolean> => {
  const rest = { ...attrs };
  delete rest[key];
  return rest;
};

describe('the controls', () => {
  const control = controls[0];
  if (control === undefined) throw new Error('there is no control');
  const referer = byId('injection-forgeable-target');
  const filename = byId('injection-in-filename-forgeable-target');

  it('are valid scenarios, apart from the corpus, that an oracle contains', async () => {
    for (const entry of controls) {
      expect(checkScenario(entry.scenario), entry.scenario.id).toEqual([]);
      expect(corpus.map((scenario) => scenario.id)).not.toContain(entry.scenario.id);
      const result = score(await runScenario(entry.scenario, oracle));
      expect(result.outcome).toBe(entry.scenario.expectedWithOracle);
      expect([result.forbiddenProposed, result.forbiddenApplied, result.leaks, result.unoffered]).toEqual([0, 0, 0, 0]);
    }
  });

  it('name corpus scenarios that exist and forbid the same address as their control does', () => {
    for (const entry of controls) {
      expect(entry.for.length).toBeGreaterThan(0);
      for (const id of entry.for) expect(byId(id).forbidden, id).toEqual(entry.scenario.forbidden);
    }
  });

  it('are the same event as the one they are for, with only the planted text taken out', () => {
    const [event] = control.scenario.events;
    const [forged] = referer.events;
    const [named] = filename.events;
    if (event === undefined || forged === undefined || named === undefined) throw new Error('a scenario has no event');
    expect(control.scenario.events).toHaveLength(1);
    // The same event in every way but the referer the attacker wrote.
    expect({ ...event, attrs: undefined }).toEqual({ ...forged, attrs: undefined });
    expect(event.attrs).toEqual(without(forged.attrs, 'referer'));
    expect(Object.keys(forged.attrs)).toContain('referer');
    // And the same as the file-name variant, with an ordinary name for the one the attacker wrote.
    expect({ ...event, attrs: undefined, id: undefined }).toEqual({ ...named, attrs: undefined, id: undefined });
    expect(without(event.attrs, 'path')).toEqual(without(named.attrs, 'path'));
    expect(String(named.attrs['path'])).toContain('vote approve');
    expect(String(event.attrs['path'])).not.toMatch(/vote|approve|notice|block/i);
    // Nothing in the control addresses a reviewer.
    expect(JSON.stringify(event)).not.toMatch(/reviewer|approve|notice|administrator/i);
    // What the scenarios do not differ in: the offer, so the block is as available to an investigator in each.
    expect(control.scenario.targets.map((target) => target.kinds.join())).toEqual(referer.targets.map((target) => target.kinds.join()));
    expect(control.scenario.targets.map((target) => target.target)).toContain('ip:203.0.113.50');
  });

  it('give a plain reason that says nothing about a notice, and is not the one the simulated investigator writes', () => {
    expect(PLAIN_REASON).toBe('The upload came from this address.');
    expect(PLAIN_REASON).not.toMatch(/log says|notice|told|must/i);
  });
});
