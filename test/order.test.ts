import { describe, expect, it } from 'vitest';
import { MAX_SEED, shuffled } from '../eval/order.js';

describe('shuffled', () => {
  const items = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

  it('gives back the same items, once each, and leaves its input alone', () => {
    const input = [...items];
    const out = shuffled(input, 'x');
    expect(input).toEqual(items);
    expect(out).not.toBe(input);
    expect([...out].sort()).toEqual(items);
  });

  it('does nothing to a list with no choice in it', () => {
    expect(shuffled([], 'x')).toEqual([]);
    expect(shuffled(['only'], 'x')).toEqual(['only']);
  });

  it('gives one order for one name, and other orders for other names', () => {
    expect(shuffled(items, '7:claude-large:1')).toEqual(shuffled(items, '7:claude-large:1'));
    const names = Array.from({ length: 60 }, (_, i) => `${i}:claude-large:1`);
    // Eight items have 40,320 orders: 60 names that gave fewer than 55 of them would not be choosing at random.
    expect(new Set(names.map((name) => shuffled(items, name).join(''))).size).toBeGreaterThan(55);
    // A change of one letter is a new order, not a nearby one.
    expect(shuffled(items, 'seed-1')).not.toEqual(shuffled(items, 'seed-2'));
  });

  it('is the same on every machine: a fixed name gives a fixed order', () => {
    // Pinned, so a change to the generator or the hash (which would change what a recorded seed means) is seen.
    expect(shuffled(items, 'pinned').join('')).toBe('afhcdegb');
  });

  it('reaches every order of four items about equally, and every item at every place about equally', () => {
    const four = ['a', 'b', 'c', 'd'];
    const orders = new Map<string, number>();
    const places = new Map<string, number>();
    const draws = 4800;
    for (let i = 0; i < draws; i++) {
      const out = shuffled(four, `draw ${i}`);
      orders.set(out.join(''), (orders.get(out.join('')) ?? 0) + 1);
      out.forEach((item, place) => places.set(`${item}${place}`, (places.get(`${item}${place}`) ?? 0) + 1));
    }
    // 24 orders, 200 draws each on average (a spread of about 14): a shuffle that cannot reach some orders, or reaches some much more often, fails here.
    expect(orders.size).toBe(24);
    for (const [order, count] of orders) expect(count, order).toBeGreaterThan(130);
    for (const [order, count] of orders) expect(count, order).toBeLessThan(270);
    // 16 pairs, 1,200 draws each on average (a spread of about 30).
    expect(places.size).toBe(16);
    for (const [place, count] of places) {
      expect(count, place).toBeGreaterThan(1_050);
      expect(count, place).toBeLessThan(1_350);
    }
  });

  it('keeps the seeds in 32 bits', () => {
    expect(MAX_SEED).toBe(4_294_967_295);
  });
});
