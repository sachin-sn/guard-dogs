import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CASE,
  PROVIDERS,
  TRIAGE_ITEMS,
  hintFor,
  liveCheck,
  main,
  renderLive,
  targetsFromEnv,
  type CheckResult,
  type LiveTarget,
} from '../examples/live-check.js';
import { block } from '../eval/sim.js';
import { ModelError, createModelRegistry, type ModelClient, type ModelRequest } from '../src/index.js';

const KEY = 'sk-test-SECRETKEY-0123456789';
const UPLOAD = '/var/www/html/uploads/avatar-4471.php';
const BOTH = { ANTHROPIC_API_KEY: KEY, GEMINI_API_KEY: `${KEY}-g` };

const json = (value: unknown, init: ResponseInit = {}): Response =>
  new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' }, ...init });

// ---- a careful analyst, answering the real prompts --------------------------------

interface Tweaks {
  /** Approve every vote. */
  approveAll?: boolean;
  /** Escalate every triage item. */
  escalateAll?: boolean;
  /** Never propose. */
  noAction?: boolean;
  /** Answer something that is not JSON. */
  garbage?: boolean;
}

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const asRecord = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});

function analyst(user: string, tweaks: Tweaks = {}): string {
  if (tweaks.garbage === true) return 'I think you should block it, honestly.';
  const items = block(user, 'items');
  if (items !== undefined) {
    return JSON.stringify({
      results: asArray(items).map((item) => ({
        id: asRecord(item)['id'],
        decision: tweaks.escalateAll === true || JSON.stringify(item).includes('avatar-4471') ? 'escalate' : 'routine',
        reason: 'scripted',
      })),
    });
  }
  if (block(user, 'case') !== undefined) {
    if (tweaks.noAction === true) return JSON.stringify({ decision: 'none', reason: 'nothing here calls for action' });
    const first = asRecord(asArray(block(user, 'evidence'))[0]);
    return JSON.stringify({ decision: 'propose', kind: 'contain.quarantine-file', target: UPLOAD, evidence: [first['id']], ttlSeconds: 600, reason: 'A PHP file in the upload directory.' });
  }
  const proposal = asRecord(block(user, 'proposal'));
  const right = proposal['kind'] === 'contain.quarantine-file' && proposal['target'] === UPLOAD;
  return JSON.stringify({ decision: tweaks.approveAll === true || right ? 'approve' : 'reject', rationale: right ? 'It fits.' : 'The evidence does not name this address.' });
}

/** A fetch that answers like the two providers, whatever the analyst says. */
function fakeFetch(tweaks: Tweaks = {}, status = 200): { fetch: typeof fetch; requests: { url: string; headers: Record<string, string>; body: Record<string, unknown> }[] } {
  const requests: { url: string; headers: Record<string, string>; body: Record<string, unknown> }[] = [];
  const impl = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    requests.push({ url: String(url), headers: init?.headers as Record<string, string>, body });
    if (status !== 200) return json({ error: { message: `quoted: ${JSON.stringify(body)}` } }, { status });
    const gemini = String(url).includes('generativelanguage');
    const user = gemini
      ? String(asRecord(asRecord(asArray(body['contents'])[0])['parts'] === undefined ? {} : asArray(asRecord(asArray(body['contents'])[0])['parts'])[0])['text'])
      : String(asRecord(asArray(body['messages'])[0])['content']);
    const text = analyst(user, tweaks);
    return gemini
      ? json({ candidates: [{ finishReason: 'STOP', content: { parts: [{ text }] } }] })
      : json({ stop_reason: 'end_turn', content: [{ type: 'text', text }] });
  };
  return { fetch: impl as typeof fetch, requests };
}

// ---- fake clients, for the checks themselves --------------------------------------

const registry = createModelRegistry([
  { id: 'claude-small', provider: 'anthropic', family: 'claude', tier: 'small', endpoint: 'https://api.anthropic.example.invalid/v1/messages', handling: 'standard', maxInputChars: 24_000 },
  { id: 'claude-large', provider: 'anthropic', family: 'claude', tier: 'large', endpoint: 'https://api.anthropic.example.invalid/v1/messages', handling: 'standard', maxInputChars: 24_000 },
]);

function target(id: 'claude-small' | 'claude-large', complete: (request: ModelRequest) => string | Promise<string>): { target: LiveTarget; requests: ModelRequest[] } {
  const requests: ModelRequest[] = [];
  const client: ModelClient = {
    model: registry.require(id),
    async complete(request) {
      requests.push(request);
      return complete(request);
    },
  };
  return { target: { name: id, provider: 'anthropic', apiModel: id === 'claude-small' ? 'claude-haiku-5-5' : 'claude-sonnet-5-5', tier: id === 'claude-small' ? 'small' : 'large', client }, requests };
}

const ticking = (): (() => number) => {
  let t = 1_000;
  return () => (t += 250);
};

describe('reading the environment', () => {
  it('checks nothing and says why when no key is set', () => {
    const { targets, skipped } = targetsFromEnv({});
    expect(targets).toEqual([]);
    expect(skipped).toEqual([
      { provider: 'anthropic', reason: 'ANTHROPIC_API_KEY is not set' },
      { provider: 'gemini', reason: 'GEMINI_API_KEY is not set' },
    ]);
    expect(targetsFromEnv({ ANTHROPIC_API_KEY: '', GEMINI_API_KEY: '' }).targets).toEqual([]);
  });

  it('makes a small and a large model for each provider that has a key', () => {
    const one = targetsFromEnv({ ANTHROPIC_API_KEY: KEY });
    expect(one.targets.map((entry) => `${entry.name}:${entry.provider}:${entry.tier}:${entry.apiModel}`)).toEqual([
      'claude-small:anthropic:small:claude-haiku-5-5',
      'claude-large:anthropic:large:claude-sonnet-5-5',
    ]);
    expect(one.skipped).toEqual([{ provider: 'gemini', reason: 'GEMINI_API_KEY is not set' }]);

    const both = targetsFromEnv(BOTH);
    expect(both.skipped).toEqual([]);
    expect(both.targets.map((entry) => entry.name)).toEqual(['claude-small', 'claude-large', 'gemini-small', 'gemini-large']);
    const gemini = both.targets.find((entry) => entry.name === 'gemini-large');
    expect(gemini?.client.model).toMatchObject({
      provider: 'gemini',
      family: 'gemini',
      tier: 'large',
      host: 'generativelanguage.googleapis.com',
      endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent',
    });
    expect(both.targets.find((entry) => entry.name === 'claude-small')?.client.model).toMatchObject({ host: 'api.anthropic.com', endpoint: 'https://api.anthropic.com/v1/messages', family: 'claude' });
    // Nothing is claimed about how the provider treats the data, and the evidence limit is modest.
    for (const entry of both.targets) expect(entry.client.model).toMatchObject({ handling: 'standard', maxInputChars: 24_000 });
  });

  it('can be limited to one provider, and still says when that one has no key', () => {
    expect(targetsFromEnv(BOTH, { only: 'gemini' }).targets.map((entry) => entry.provider)).toEqual(['gemini', 'gemini']);
    expect(targetsFromEnv(BOTH, { only: 'gemini' }).skipped).toEqual([{ provider: 'anthropic', reason: 'not selected' }]);
    expect(targetsFromEnv({ ANTHROPIC_API_KEY: KEY }, { only: 'gemini' }).skipped).toEqual([
      { provider: 'anthropic', reason: 'not selected' },
      { provider: 'gemini', reason: 'GEMINI_API_KEY is not set' },
    ]);
  });

  it('takes other model names from the environment, and ignores an empty setting', () => {
    const { targets } = targetsFromEnv({ ...BOTH, GUARD_DOGS_CLAUDE_LARGE: 'claude-opus-5-5', GUARD_DOGS_GEMINI_SMALL: 'gemini-4-argon', GUARD_DOGS_GEMINI_LARGE: '' });
    const names = Object.fromEntries(targets.map((entry) => [entry.name, entry.apiModel]));
    expect(names).toEqual({ 'claude-small': 'claude-haiku-5-5', 'claude-large': 'claude-opus-5-5', 'gemini-small': 'gemini-4-argon', 'gemini-large': 'gemini-3.8-flash' });
    expect(targets.find((entry) => entry.name === 'gemini-small')?.client.model.endpoint).toContain('/models/gemini-4-argon:generateContent');
  });

  it('refuses a model name that could change where the request goes', () => {
    for (const bad of ['../x', 'a/b', 'a?key=1', 'a b', 'a:generateContent', '-x', 'x'.repeat(65), 'x\n']) {
      expect(() => targetsFromEnv({ GEMINI_API_KEY: KEY, GUARD_DOGS_GEMINI_LARGE: bad })).toThrow(/GUARD_DOGS_GEMINI_LARGE is not a model name/);
      expect(() => targetsFromEnv({ ANTHROPIC_API_KEY: KEY, GUARD_DOGS_CLAUDE_SMALL: bad })).toThrow(/GUARD_DOGS_CLAUDE_SMALL is not a model name/);
    }
    // A provider that is not being checked is not checked for its settings either.
    expect(() => targetsFromEnv({ ANTHROPIC_API_KEY: KEY, GUARD_DOGS_GEMINI_LARGE: '../x' })).not.toThrow();
  });

  it('keeps the provider table honest about the defaults named in the notes', () => {
    expect(PROVIDERS.anthropic.models.small.fallback).toBe('claude-haiku-5-5');
    expect(PROVIDERS.anthropic.models.large.fallback).toBe('claude-sonnet-5-5');
    expect(PROVIDERS.gemini.models.small.fallback).toBe('gemini-3.5-flash-lite');
    expect(PROVIDERS.gemini.models.large.fallback).toBe('gemini-3.8-flash');
  });

  it('sends each provider the request its adapter builds, with the key in a header only', async () => {
    const { fetch, requests } = fakeFetch();
    const { targets } = targetsFromEnv(BOTH, { transport: { fetch }, maxOutputTokens: 640 });
    const signal = new AbortController().signal;
    await targets.find((entry) => entry.name === 'claude-small')?.client.complete({ system: 's', user: 'u' }, signal);
    await targets.find((entry) => entry.name === 'gemini-small')?.client.complete({ system: 's', user: 'u' }, signal);

    const [claude, gemini] = requests;
    expect(claude?.url).toBe('https://api.anthropic.com/v1/messages');
    expect(claude?.headers).toMatchObject({ 'x-api-key': KEY, 'anthropic-version': '2023-06-01' });
    expect(claude?.body).toMatchObject({ model: 'claude-haiku-5-5', max_tokens: 640, system: 's' });

    expect(gemini?.url).toBe('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent');
    expect(gemini?.headers).toMatchObject({ 'x-goog-api-key': `${KEY}-g` });
    expect(gemini?.body).not.toHaveProperty('model');
    expect(gemini?.body).toMatchObject({ generationConfig: { maxOutputTokens: 640 } });

    for (const request of requests) {
      expect(request.url).not.toContain(KEY);
      expect(JSON.stringify(request.body)).not.toContain(KEY);
    }
  });

  it('uses 800 output tokens unless told otherwise, and refuses a limit the client refuses', async () => {
    const { fetch, requests } = fakeFetch();
    const { targets } = targetsFromEnv({ ANTHROPIC_API_KEY: KEY }, { transport: { fetch } });
    await targets[0]?.client.complete({ system: 's', user: 'u' }, new AbortController().signal);
    expect(requests[0]?.body).toMatchObject({ max_tokens: 800 });
    expect(() => targetsFromEnv({ ANTHROPIC_API_KEY: KEY }, { maxOutputTokens: 5 })).toThrow(/maxOutputTokens/);
  });

  it('reads the key when a request is sent, so a rotated key is picked up', async () => {
    const { fetch, requests } = fakeFetch();
    const env: Record<string, string | undefined> = { ANTHROPIC_API_KEY: 'first-key' };
    const { targets } = targetsFromEnv(env, { transport: { fetch } });
    const signal = new AbortController().signal;
    await targets[0]?.client.complete({ system: 's', user: 'u' }, signal);
    env['ANTHROPIC_API_KEY'] = 'second-key';
    await targets[0]?.client.complete({ system: 's', user: 'u' }, signal);
    expect(requests.map((request) => request.headers['x-api-key'])).toEqual(['first-key', 'second-key']);
  });
});

describe('what to try when a call fails', () => {
  const host = 'api.example.invalid';

  it('says what the kind of failure usually means, and names the host for a network failure', () => {
    expect(hintFor({ kind: 'config' }, host)).toMatch(/trailing space or newline/);
    expect(hintFor({ kind: 'http', status: 401 }, host)).toMatch(/401.*did not accept the key/);
    expect(hintFor({ kind: 'http', status: 403 }, host)).toMatch(/403.*no access to this model/);
    expect(hintFor({ kind: 'http', status: 404 }, host)).toMatch(/404.*model name/);
    expect(hintFor({ kind: 'http', status: 400 }, host)).toMatch(/400.*key.*model name.*--max-output-tokens/);
    expect(hintFor({ kind: 'http', status: 429 }, host)).toMatch(/429.*credits or quota/);
    expect(hintFor({ kind: 'http', status: 500 }, host)).toMatch(/500.*try again/);
    expect(hintFor({ kind: 'http', status: 503 }, host)).toMatch(/503.*try again/);
    expect(hintFor({ kind: 'http', status: 499 }, host)).toBe('HTTP 499');
    expect(hintFor({ kind: 'http', status: 418 }, host)).toBe('HTTP 418');
    expect(hintFor({ kind: 'http' }, host)).toBe('HTTP ?');
    expect(hintFor({ kind: 'network' }, host)).toContain(host);
    expect(hintFor({ kind: 'refused' }, host)).toMatch(/declined/);
    expect(hintFor({ kind: 'output' }, host)).toMatch(/cut off.*--max-output-tokens/);
    expect(hintFor({ kind: 'response' }, host)).toMatch(/form the adapter does not read/);
    expect(hintFor({ kind: 'input' }, host)).toBe('failed (input)');
  });
});

describe('the checks', () => {
  const scripted = (tweaks: Tweaks = {}) => (request: ModelRequest) => analyst(request.user, tweaks);

  it('asks a small model to triage, and a large model to investigate and to vote three times', async () => {
    const small = target('claude-small', scripted());
    const large = target('claude-large', scripted());
    const results = await liveCheck([small.target, large.target], { now: ticking() });
    expect(small.requests).toHaveLength(1);
    expect(large.requests).toHaveLength(4);
    expect(results.map((result) => `${result.target}/${result.check}`)).toEqual([
      'claude-small/triage',
      'claude-large/investigation',
      'claude-large/vote on the right action',
      'claude-large/vote on the wrong target',
      'claude-large/vote with a notice in the log',
    ]);
    expect(results.every((result) => result.worked && result.expected === true)).toBe(true);
    expect(results.every((result) => result.ms === 250)).toBe(true);
  });

  it('describes what the model did in each check', async () => {
    const results = await liveCheck([target('claude-small', scripted()).target, target('claude-large', scripted()).target]);
    const byCheck = Object.fromEntries(results.map((result) => [result.check, result.detail]));
    expect(byCheck['triage']).toBe('web-root upload: escalate; cron job running curl: routine');
    expect(byCheck['investigation']).toBe(`proposed contain.quarantine-file on ${UPLOAD}`);
    expect(byCheck['vote on the right action']).toBe('approve: It fits.');
    expect(byCheck['vote on the wrong target']).toBe('reject: The evidence does not name this address.');
  });

  it('puts the made-up cases in the prompts: a real action, a wrong target, and a notice in only one', async () => {
    const large = target('claude-large', scripted());
    await liveCheck([large.target]);
    const [investigation, right, wrong, notice] = large.requests;
    expect(investigation?.user).toContain(UPLOAD);
    expect(investigation?.user).toContain('shop-web:/upload');
    expect(JSON.stringify(block(right?.user ?? '', 'proposal'))).toContain('contain.quarantine-file');
    expect(JSON.stringify(block(wrong?.user ?? '', 'proposal'))).toContain('ip_aaaaaaaaaaaa');
    expect(JSON.stringify(block(wrong?.user ?? '', 'evidence'))).not.toContain('ip_aaaaaaaaaaaa');
    expect(JSON.stringify(block(wrong?.user ?? '', 'evidence'))).not.toContain('SYSTEM NOTICE');
    expect(JSON.stringify(block(notice?.user ?? '', 'proposal'))).toContain('ip_aaaaaaaaaaaa');
    expect(JSON.stringify(block(notice?.user ?? '', 'evidence'))).toContain('SYSTEM NOTICE');
    expect(JSON.stringify(block(right?.user ?? '', 'evidence'))).not.toContain('SYSTEM NOTICE');
    // Nothing real: the case and items use documentation-style names only.
    expect(JSON.stringify([TRIAGE_ITEMS, CASE])).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  });

  it('says "differs" for a model that works but judges otherwise', async () => {
    const credulous = await liveCheck([target('claude-small', scripted({ escalateAll: true })).target, target('claude-large', scripted({ approveAll: true })).target]);
    const by = Object.fromEntries(credulous.map((result) => [result.check, result]));
    expect(by['triage']).toMatchObject({ worked: true, expected: false, detail: 'web-root upload: escalate; cron job running curl: escalate' });
    expect(by['investigation']).toMatchObject({ worked: true, expected: true });
    expect(by['vote on the right action']).toMatchObject({ worked: true, expected: true });
    expect(by['vote on the wrong target']).toMatchObject({ worked: true, expected: false });
    expect(by['vote with a notice in the log']).toMatchObject({ worked: true, expected: false });

    const quiet = await liveCheck([target('claude-large', scripted({ noAction: true })).target]);
    expect(quiet[0]).toMatchObject({ check: 'investigation', worked: true, expected: false, detail: 'no action: nothing here calls for action' });
  });

  it('says a proposal the investigator had to refuse is a setup problem, not a judgment', async () => {
    const wrongTarget = target('claude-large', (request) =>
      block(request.user, 'case') === undefined
        ? analyst(request.user)
        : JSON.stringify({ decision: 'propose', kind: 'contain.quarantine-file', target: '/etc/passwd', evidence: ['evt-1'], reason: 'x' }),
    );
    const [first] = await liveCheck([wrongTarget.target]);
    expect(first).toMatchObject({ check: 'investigation', worked: false });
    expect(first?.detail).toMatch(/proposal was refused \(rejected:unknown-target\)/);
  });

  it('reports a model that answers in prose as failed, in each role, without quoting it', async () => {
    const results = await liveCheck([target('claude-small', scripted({ garbage: true })).target, target('claude-large', scripted({ garbage: true })).target]);
    expect(results.every((result) => !result.worked)).toBe(true);
    const by = Object.fromEntries(results.map((result) => [result.check, result.detail]));
    expect(by['triage']).toMatch(/did not settle the items \(ModelOutputError\)/);
    expect(by['investigation']).toMatch(/did not answer \(ModelOutputError\)/);
    expect(by['vote on the right action']).toMatch(/no usable answer.*--max-output-tokens/);
    for (const detail of Object.values(by)) expect(detail).not.toContain('honestly');
  });

  it('turns each kind of client failure into its hint, in every role', async () => {
    const failing = (error: ModelError) => (): string => {
      throw error;
    };
    const cases: [ModelError, RegExp][] = [
      [new ModelError('http', 'x', 401), /401.*did not accept the key/],
      [new ModelError('http', 'x', 404), /404.*model name/],
      [new ModelError('network', 'x'), /api\.anthropic\.example\.invalid/],
      [new ModelError('config', 'x'), /trailing space or newline/],
    ];
    for (const [error, expected] of cases) {
      const results = await liveCheck([target('claude-small', failing(error)).target, target('claude-large', failing(error)).target]);
      expect(results).toHaveLength(5);
      for (const result of results) {
        expect(result.worked).toBe(false);
        expect(result.expected).toBeUndefined();
        expect(result.detail).toMatch(expected);
      }
    }
  });

  it('reports an error that is not a ModelError by its name only', async () => {
    const boom = target('claude-large', () => {
      throw Object.assign(new Error(`could not reach host with key ${KEY}`), { name: 'WeirdError' });
    });
    const results = await liveCheck([boom.target]);
    expect(results.every((result) => !result.worked)).toBe(true);
    const text = JSON.stringify(results);
    expect(text).toContain('WeirdError');
    expect(text).not.toContain(KEY);
  });

  it('does not carry one call\'s outcome into the next check of the same model', async () => {
    let calls = 0;
    const flaky = target('claude-large', (request) => {
      calls += 1;
      if (calls === 1) return analyst(request.user);
      throw new ModelError('http', 'x', calls === 2 ? 429 : 503);
    });
    const results = await liveCheck([flaky.target]);
    expect(results[0]).toMatchObject({ worked: true });
    expect(results[0]?.reply).toBeDefined();
    // The failures have their own status, and no reply left over from the call before.
    expect(results[1]).toMatchObject({ worked: false });
    expect(results[1]?.detail).toMatch(/429/);
    expect(results[1]?.reply).toBeUndefined();
    expect(results[2]?.detail).toMatch(/503/);
    expect(results[2]?.reply).toBeUndefined();

    let second = 0;
    const recovers = target('claude-large', (request) => {
      second += 1;
      if (second === 1) throw new ModelError('http', 'x', 401);
      return analyst(request.user);
    });
    const after = await liveCheck([recovers.target]);
    expect(after[0]).toMatchObject({ worked: false });
    expect(after[1]).toMatchObject({ worked: true, expected: true });
    expect(after[1]?.detail).not.toMatch(/401/);
  });

  it('counts a triage that left an item to the fallback as failed', async () => {
    const partial = target('claude-small', (request) => {
      const items = asArray(block(request.user, 'items'));
      return JSON.stringify({ results: [{ id: asRecord(items[0])['id'], decision: 'escalate', reason: 'scripted' }] });
    });
    const [first] = await liveCheck([partial.target]);
    expect(first).toMatchObject({ check: 'triage', worked: false });
    expect(first?.detail).toMatch(/did not settle the items/);
  });

  it('judges triage on both items, and the investigation on both kind and target', async () => {
    const routine = await liveCheck([target('claude-small', (request) => JSON.stringify({ results: asArray(block(request.user, 'items')).map((item) => ({ id: asRecord(item)['id'], decision: 'routine' })) })).target]);
    expect(routine[0]).toMatchObject({ worked: true, expected: false, detail: 'web-root upload: routine; cron job running curl: routine' });

    const backwards = await liveCheck([
      target('claude-small', (request) => JSON.stringify({ results: asArray(block(request.user, 'items')).map((item, index) => ({ id: asRecord(item)['id'], decision: index === 0 ? 'routine' : 'escalate' })) })).target,
    ]);
    expect(backwards[0]).toMatchObject({ worked: true, expected: false });

    const rateLimit = await liveCheck([
      target('claude-large', (request) =>
        block(request.user, 'case') === undefined
          ? analyst(request.user)
          : JSON.stringify({ decision: 'propose', kind: 'contain.rate-limit', target: 'shop-web:/upload', evidence: ['evt-1'], ttlSeconds: 600, reason: 'Slow it down.' }),
      ).target,
    ]);
    expect(rateLimit[0]).toMatchObject({ check: 'investigation', worked: true, expected: false, detail: 'proposed contain.rate-limit on shop-web:/upload' });
  });

  it('counts an abstention as not approving', async () => {
    const abstains = await liveCheck([
      target('claude-large', (request) => (block(request.user, 'proposal') === undefined ? analyst(request.user) : JSON.stringify({ decision: 'abstain', rationale: 'Cannot tell.' }))).target,
    ]);
    const by = Object.fromEntries(abstains.map((result) => [result.check, result]));
    expect(by['vote on the right action']).toMatchObject({ worked: true, expected: false, detail: 'abstain: Cannot tell.' });
    expect(by['vote on the wrong target']).toMatchObject({ worked: true, expected: true });
    expect(by['vote with a notice in the log']).toMatchObject({ worked: true, expected: true });
  });

  it('stops every kind of check at the deadline, for a model that never answers', async () => {
    const hangs = (id: 'claude-small' | 'claude-large') => {
      const requests: ModelRequest[] = [];
      const client: ModelClient = {
        model: registry.require(id),
        complete(request, signal) {
          requests.push(request);
          // Like the real transport: stop when the signal says so.
          return new Promise<string>((_, reject) => signal.addEventListener('abort', () => reject(new ModelError('network', 'the call failed or timed out'))));
        },
      };
      return { name: id, provider: 'anthropic', apiModel: 'x', tier: id === 'claude-small' ? 'small' : 'large', client } as LiveTarget;
    };
    const started = Date.now();
    const results = await liveCheck([hangs('claude-small'), hangs('claude-large')], { timeoutMs: 50 });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(results).toHaveLength(5);
    for (const result of results) {
      expect(result.worked).toBe(false);
      expect(result.detail).toMatch(/api\.anthropic\.example\.invalid|did not settle|did not answer/);
    }
    expect(results.filter((result) => result.check.startsWith('vote')).every((result) => /no answer; check the connection/.test(result.detail))).toBe(true);
  });

  it('does not blame the key for a later answer that merely is not usable', async () => {
    let calls = 0;
    const flaky = target('claude-large', () => {
      calls += 1;
      if (calls === 1) throw new ModelError('http', 'x', 401);
      return 'not json at all';
    });
    const results = await liveCheck([flaky.target]);
    expect(results[0]?.detail).toMatch(/401/);
    for (const result of results.slice(1)) {
      expect(result.worked).toBe(false);
      expect(result.detail).not.toMatch(/401/);
    }
    expect(results[2]?.detail).toMatch(/no usable answer/);
  });

  it('names the evidence view in the vote prompt it sends', async () => {
    const large = target('claude-large', scripted());
    await liveCheck([large.target]);
    expect(large.requests[1]?.user).toContain('"raw-logs" view');
  });

  describe('with a slow model', () => {
    afterEach(() => vi.useRealTimers());

    const slow = (id: 'claude-small' | 'claude-large', delayMs: number) =>
      target(id, (request) => new Promise<string>((resolve) => setTimeout(() => resolve(analyst(request.user)), delayMs)));

    it('waits as long as it was told to, not for the default of the triage and the investigator', async () => {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
      const pending = liveCheck([slow('claude-small', 70_000).target, slow('claude-large', 70_000).target], { timeoutMs: 200_000 });
      await vi.advanceTimersByTimeAsync(70_000 * 5 + 1_000);
      const results = await pending;
      expect(results.filter((result) => result.check === 'triage' || result.check === 'investigation').map((result) => [result.check, result.worked])).toEqual([
        ['triage', true],
        ['investigation', true],
      ]);
    });

    it('and gives up on a slow model when it was told to wait less', async () => {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
      const pending = liveCheck([slow('claude-small', 30_000).target], { timeoutMs: 5_000 });
      await vi.advanceTimersByTimeAsync(40_000);
      const [first] = await pending;
      expect(first?.worked).toBe(false);
    });
  });

  it('cleans what it keeps of a reply, and keeps it short', async () => {
    const messy = target('claude-large', (request) => {
      const real = analyst(request.user);
      return block(request.user, 'proposal') === undefined ? real : `${real.slice(0, -1)},"note":"\u001b[31m${'x'.repeat(600)}"}`;
    });
    const results = await liveCheck([messy.target]);
    const vote = results.find((result) => result.check === 'vote on the right action');
    expect(vote?.reply).toBeDefined();
    expect(vote?.reply?.length).toBeLessThanOrEqual(300);
    // eslint-disable-next-line no-control-regex
    expect(vote?.reply).not.toMatch(/[\u0000-\u001f]/);
  });

  it('gives each check a deadline', async () => {
    const hang = target('claude-large', () => new Promise<string>(() => undefined));
    const started = Date.now();
    const [first] = await liveCheck([{ ...hang.target, tier: 'small' }], { timeoutMs: 40 });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(first?.worked).toBe(false);
  });
});

describe('the report', () => {
  const small = target('claude-small', () => '').target;
  const large = target('claude-large', () => '').target;
  const make = (extra: Partial<CheckResult>): CheckResult => ({ target: 'claude-large', check: 'investigation', worked: true, expected: true, detail: 'proposed it', ms: 1_234, ...extra });

  it('shows one line per check with its state, time and detail', () => {
    const lines = renderLive(
      [small, large],
      [{ provider: 'gemini', reason: 'GEMINI_API_KEY is not set' }],
      [
        make({ target: 'claude-small', check: 'triage', detail: 'fine' }),
        make({ check: 'investigation', expected: false, detail: 'no action' }),
        make({ check: 'vote on the right action', worked: false, expected: undefined, detail: 'HTTP 401: no' }),
      ],
    ).join('\n');
    expect(lines).toContain('gemini: skipped, GEMINI_API_KEY is not set');
    expect(lines).toContain('claude-small  (anthropic claude-haiku-5-5)');
    expect(lines).toContain('claude-large  (anthropic claude-sonnet-5-5)');
    expect(lines).toMatch(/triage\s+ok\s+1\.2s\s+fine/);
    expect(lines).toMatch(/investigation\s+differs\s+1\.2s\s+no action/);
    expect(lines).toMatch(/vote on the right action\s+FAILED\s+1\.2s\s+HTTP 401: no/);
    expect(lines).toContain('2 of 3 calls worked; of those, 1 of 2 gave the answer a careful analyst would.');
    expect(lines).toContain('Fix the FAILED lines first');
    expect(lines).toContain('"differs" means the call worked');
  });

  it('does not count judgments when no call worked', () => {
    const text = renderLive([large], [], [make({ worked: false, expected: undefined, detail: 'HTTP 401' })]).join('\n');
    expect(text).toContain('0 of 1 calls worked.');
    expect(text).not.toContain('of those');
  });

  it('keeps its advice for when it applies, and shows replies only on request', () => {
    const clean = [make({ reply: 'the reply' })];
    const quiet = renderLive([large], [], clean).join('\n');
    expect(quiet).toContain('1 of 1 calls worked; of those, 1 of 1 gave');
    expect(quiet).not.toContain('Fix the FAILED');
    expect(quiet).not.toContain('"differs"');
    expect(quiet).not.toContain('the reply');
    expect(renderLive([large], [], clean, true).join('\n')).toContain('reply: the reply');
    expect(renderLive([large], [], [make({ reply: undefined })], true).join('\n')).not.toContain('reply:');
  });
});

describe('the command line', () => {
  const run = async (args: string[], env: Record<string, string | undefined>, fetch?: typeof globalThis.fetch): Promise<{ code: number; text: string }> => {
    const lines: string[] = [];
    const code = await main(args, env, (line) => lines.push(line), fetch === undefined ? undefined : { fetch });
    return { code, text: lines.join('\n') };
  };

  it('says what to set when there is nothing to check, and exits 2', async () => {
    const { code, text } = await run([], {});
    expect(code).toBe(2);
    expect(text).toContain('LIVE CHECK');
    expect(text).toContain('ANTHROPIC_API_KEY is not set');
    expect(text).toContain('Set ANTHROPIC_API_KEY and/or GEMINI_API_KEY');
  });

  it('runs every check against both providers and exits 0 when all of it works', async () => {
    const { fetch, requests } = fakeFetch();
    const { code, text } = await run([], BOTH, fetch);
    expect(code).toBe(0);
    expect(requests).toHaveLength(10);
    expect(requests.filter((request) => request.url.includes('generativelanguage'))).toHaveLength(5);
    expect(text).toContain('10 of 10 calls worked; of those, 10 of 10 gave the answer a careful analyst would.');
    expect(text).not.toContain('FAILED');
    expect(text).not.toContain(KEY);
  });

  it('exits 0 for a model that works but differs, and says so', async () => {
    const { fetch } = fakeFetch({ approveAll: true });
    const { code, text } = await run(['--only', 'anthropic'], BOTH, fetch);
    expect(code).toBe(0);
    expect(text).toContain('anthropic claude-sonnet-5-5');
    expect(text).not.toContain('gemini-large');
    expect(text).toContain('differs');
    expect(text).toContain('That is not a setup problem');
  });

  it('exits 1 when a call fails, with a hint and without the key or the provider\'s words', async () => {
    const { fetch, requests } = fakeFetch({}, 401);
    const { code, text } = await run(['--only', 'gemini'], BOTH, fetch);
    expect(code).toBe(1);
    expect(requests).toHaveLength(5);
    expect(text).toContain('FAILED');
    expect(text).toContain('HTTP 401: the provider did not accept the key');
    expect(text).toContain('0 of 5 calls worked.');
    expect(text).not.toContain(KEY);
    expect(text).not.toContain('quoted');
  });

  it('exits 1 when only some of the calls fail', async () => {
    const good = fakeFetch();
    const mixed = ((url: string | URL | Request, init?: RequestInit) =>
      String(url).includes('generativelanguage') ? Promise.resolve(json({ error: 'no' }, { status: 401 })) : good.fetch(url, init)) as typeof fetch;
    const { code, text } = await run([], BOTH, mixed);
    expect(code).toBe(1);
    expect(text).toContain('5 of 10 calls worked');
    expect(text).toMatch(/gemini-small[\s\S]*FAILED/);
    expect(text).toMatch(/claude-large[\s\S]*ok/);
  });

  it('gives each call the time it was told to, and no more', async () => {
    const hanging = ((_url: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))))) as typeof fetch;
    const started = Date.now();
    const { code, text } = await run(['--only', 'anthropic', '--timeout-ms', '60'], BOTH, hanging);
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(code).toBe(1);
    expect(text).toContain('0 of 5 calls worked.');
    expect(text).toContain('api.anthropic.com');
  });

  it('passes the output limit and timeout on, and shows replies when asked', async () => {
    const { fetch, requests } = fakeFetch();
    const { text } = await run(['--only', 'anthropic', '--max-output-tokens', '321', '--timeout-ms', '5000', '--show-replies'], BOTH, fetch);
    expect(requests.every((request) => request.body['max_tokens'] === 321)).toBe(true);
    expect(text).toContain('reply: ');
    expect((await run(['--only', 'anthropic'], BOTH, fakeFetch().fetch)).text).not.toContain('reply: ');
  });

  it('refuses options it does not understand', async () => {
    await expect(run(['--only', 'openai'], BOTH)).rejects.toThrow(/--only is anthropic or gemini/);
    await expect(run(['--only'], BOTH)).rejects.toThrow(/--only is anthropic or gemini/);
    await expect(run(['--max-output-tokens', 'many'], BOTH)).rejects.toThrow(/--max-output-tokens needs a positive whole number/);
    await expect(run(['--timeout-ms'], BOTH)).rejects.toThrow(/--timeout-ms needs a positive whole number/);
    await expect(run(['--max-output-tokens', '1.5'], BOTH)).rejects.toThrow(/positive whole number/);
    await expect(run(['--timeout-ms', '0'], BOTH)).rejects.toThrow(/positive whole number/);
    await expect(run(['--timeout-ms', '-5'], BOTH)).rejects.toThrow(/positive whole number/);
  });
});
