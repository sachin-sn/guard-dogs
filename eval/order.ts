/**
 * The order a model's calls are made in.
 *
 * The first seven live runs asked every case in the order the plan lists it:
 * the unmarked arm of a control first, then the tagged one, then the one with
 * the paragraph. Whatever changes over the minutes a run takes (a provider's
 * load, a model update behind one name, the pacing) then falls on one arm, and
 * the difference between arms is no longer only the arm. Asking the calls in a
 * random order, a different one for each model and each run, spreads that over
 * the arms.
 *
 * The order comes from a seed, so a run can be repeated and the order a run
 * used can be written down: the same seed and name give the same order on any
 * machine.
 */

import { createHash } from 'node:crypto';

/** The largest seed: it is kept in 32 bits. */
export const MAX_SEED = 0xffff_ffff;

/** A generator of numbers from 0 up to but not including 1, from a 32-bit state (mulberry32). */
function generator(state: number): () => number {
  let a = state >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * The items in a random order that `name` fixes (Fisher-Yates), as a new list.
 * Every order is equally likely; the input is not changed. The name is hashed,
 * so names that differ in one letter give orders that have nothing in common.
 */
export function shuffled<T>(items: readonly T[], name: string): T[] {
  const out = [...items];
  const random = generator(createHash('sha256').update(name).digest().readUInt32BE(0));
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}
