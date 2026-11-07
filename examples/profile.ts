/**
 * Profile: how do the models you configured actually do on the evaluation corpus?
 *
 *   npm run profile                      show the plan and the number of calls; send nothing
 *   npm run profile -- --run             send the calls and print the report
 *   npm run profile -- --run --runs 5 --json profile.json
 *   npm run profile -- --run --only anthropic
 *   npm run profile -- --run --only gemini --min-gap-ms 15000
 *   npm run profile -- --run --votes 16 --investigations 0 --triage 0 --all-views
 *
 * This spends API credit, so nothing is sent without `--run`, and the plan is
 * refused if it is bigger than `--max-calls` (default 300). The default plan is
 * about 200 calls with two large and two small models: each large model gets 16
 * votes, 8 investigations, each asked 3 times, and each small model gets 10
 * triage requests, each asked 3 times.
 *
 * The cases are the corpus's own, run through the real pipeline offline (see
 * `eval/live.ts`); every address, host and path is invented. Keys come from the
 * same variables as `npm run live-check`, a provider without one is skipped, and
 * a key is only ever placed in a request header.
 *
 * A provider that limits calls per minute (free keys often do) answers a burst
 * with HTTP 429, and the report would show a model that never answers. The report
 * says so, by kind; `--min-gap-ms` spaces one model's calls to stay under it.
 *
 * `--all-views` asks each chosen proposal in every evidence view it has, not
 * only the one the plan gave it, and adds a VIEWS section to the report. A note
 * that one view carries is then told apart from one that all of them carry.
 * Those extra calls come on top of the default plan and are counted in it.
 *
 * Run `npm run live-check` first: a profile on a model that does not answer
 * measures the outage.
 */

import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { collectCases, callCount, callHealth, plan, renderMeasured, renderPlan, DEFAULT_LIMITS, DEFAULT_TIMEOUT_MS, MAX_RUNS, measure, type Limits, type Participant } from '../eval/live.js';
import { DEFAULT_MAX_OUTPUT_TOKENS, PROVIDERS, loadDotEnv, targetsFromEnv, type Provider } from './live-check.js';
import type { TransportOptions } from '../src/index.js';

const DEFAULT_MAX_CALLS = 300;
const MAX_GAP_MS = 300_000;

function whole(args: readonly string[], name: string, min: number): number | undefined {
  const at = args.indexOf(name);
  if (at === -1) return undefined;
  const raw = args[at + 1];
  const value = raw === undefined || raw.trim() === '' ? Number.NaN : Number(raw);
  if (!Number.isInteger(value) || value < min) throw new RangeError(`${name} needs a whole number, ${min} or more`);
  return value;
}

/** Returns the exit code: 0 done (or planned), 1 a call or the cap stopped it, 2 nothing was configured. */
export async function main(
  args: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  print: (line: string) => void = console.log,
  transport?: TransportOptions,
): Promise<number> {
  const onlyAt = args.indexOf('--only');
  const named = onlyAt === -1 ? undefined : args[onlyAt + 1];
  if (onlyAt !== -1 && named !== 'anthropic' && named !== 'gemini') throw new RangeError('--only is anthropic or gemini');
  const only: Provider | undefined = named === 'anthropic' || named === 'gemini' ? named : undefined;

  const limits: Limits = {
    votes: whole(args, '--votes', 0) ?? DEFAULT_LIMITS.votes,
    investigations: whole(args, '--investigations', 0) ?? DEFAULT_LIMITS.investigations,
    triage: whole(args, '--triage', 0) ?? DEFAULT_LIMITS.triage,
    runs: whole(args, '--runs', 1) ?? DEFAULT_LIMITS.runs,
    ...(args.includes('--all-views') ? { allViews: true } : {}),
  };
  if (limits.runs > MAX_RUNS) throw new RangeError(`--runs is at most ${MAX_RUNS}`);
  const maxCalls = whole(args, '--max-calls', 1) ?? DEFAULT_MAX_CALLS;
  const maxOutputTokens = whole(args, '--max-output-tokens', 1);
  const timeoutMs = whole(args, '--timeout-ms', 1);
  const minGapMs = whole(args, '--min-gap-ms', 0);
  if (minGapMs !== undefined && minGapMs > MAX_GAP_MS) throw new RangeError(`--min-gap-ms is at most ${MAX_GAP_MS}`);
  const jsonAt = args.indexOf('--json');
  const jsonFile = jsonAt === -1 ? undefined : args[jsonAt + 1];
  if (jsonAt !== -1 && (jsonFile === undefined || jsonFile.startsWith('--'))) throw new RangeError('--json needs a file name');

  const configured = targetsFromEnv(env, {
    ...(only === undefined ? {} : { only }),
    ...(maxOutputTokens === undefined ? {} : { maxOutputTokens }),
    ...(transport === undefined ? {} : { transport }),
  });

  print('PROFILE. Sends labelled made-up cases (no real logs) to the models you configured, and counts what they do.');
  if (configured.targets.length === 0) {
    for (const entry of configured.skipped) print(`  ${entry.provider}: skipped, ${entry.reason}`);
    print('');
    print('Nothing to profile. Set ANTHROPIC_API_KEY and/or GEMINI_API_KEY (for example in a .env file, which git ignores).');
    return 2;
  }
  for (const entry of configured.skipped) print(`  ${entry.provider}: skipped, ${entry.reason}`);

  const participants: Participant[] = configured.targets.map((target) => ({
    name: target.name,
    family: PROVIDERS[target.provider].family,
    tier: target.tier,
    client: target.client,
    api: target.apiModel,
  }));
  const chosen = plan(await collectCases(), limits);
  const large = participants.filter((participant) => participant.tier === 'large').length;
  const calls = callCount(chosen, large, participants.length - large);

  print('');
  for (const line of renderPlan(chosen, participants)) print(line);
  if (minGapMs !== undefined && minGapMs > 0) {
    // The longest queue: a large model's votes and investigations, or a small model's triage requests, once for each run.
    const longest = Math.max(large > 0 ? (chosen.votes.length + chosen.variants.length + chosen.investigations.length) * limits.runs : 0, participants.length > large ? chosen.triage.length * limits.runs : 0);
    print(`  pacing:         at least ${minGapMs} ms between one model's calls, so the slowest model takes at least ${Math.ceil((longest * minGapMs) / 60_000)} minutes`);
  }
  if (calls > maxCalls) {
    print('');
    print(`That is more than --max-calls ${maxCalls}. Lower --runs, --votes, --investigations or --triage, or raise --max-calls if you mean to spend it.`);
    return 1;
  }
  if (!args.includes('--run')) {
    print('');
    print('Nothing was sent. Add --run to send these calls.');
    return 0;
  }

  print('');
  let last = 0;
  const measured = await measure(participants, chosen, {
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
    ...(minGapMs === undefined ? {} : { minGapMs }),
    onProgress: (done, total) => {
      if (done === total || done - last >= 25) {
        last = done;
        print(`  ${done} of ${total} calls done`);
      }
    },
  });
  for (const line of renderMeasured(measured, chosen, participants)) print(line);

  if (jsonFile !== undefined) {
    // Counts and outcomes only: what the models wrote is not kept.
    const models = participants.map((participant) => ({ name: participant.name, family: participant.family, tier: participant.tier, api: participant.api }));
    // The settings are what the run used, so a file can say how it was made.
    const settings = { minGapMs: minGapMs ?? 0, maxOutputTokens: maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS, timeoutMs: timeoutMs ?? DEFAULT_TIMEOUT_MS };
    fs.writeFileSync(jsonFile, `${JSON.stringify({ limits, settings, calls, models, ...measured }, null, 2)}\n`);
    print(`\nwrote ${jsonFile}`);
  }
  const failed = participants.reduce((sum, participant) => sum + callHealth(measured, participant.name).failed, 0);
  if (failed > 0) print(`\n${failed} calls got no usable answer (by kind, above). They count as silent dogs, so fix the cause before reading the rates.`);
  return failed > 0 ? 1 : 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const loaded = loadDotEnv('.env');
  if (loaded !== 'loaded' && loaded !== 'missing') console.error(loaded);
  process.exitCode = await main(process.argv.slice(2), process.env);
}
