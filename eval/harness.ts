/**
 * Run one scenario through the real system.
 *
 * Everything is the code under test (masking, tier 1, throttling, the
 * orchestrator, triage, the investigators, the panel, the gate, the executor,
 * the audit log) except three things: the clock, which is a fake one so a
 * scenario that spans forty minutes takes milliseconds; the firewall and other
 * controls, which only record what they were asked to do; and the models,
 * which a profile answers for.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  AuditLog,
  Executor,
  Investigator,
  ModelDog,
  Orchestrator,
  Panel,
  Pipeline,
  TriageDog,
  createGatePolicy,
  createMasker,
  createModelRegistry,
  defaultRulesConfig,
  planPanel,
  rawView,
  summaryView,
  type Case,
  type CaseTarget,
  type ControlAdapter,
  type CycleReport,
  type ModelClient,
  type ModelRequest,
  type Notification,
  type ProposedAction,
  type SubmitStatus,
} from '../src/index.js';
import type { Containment, Scenario } from './scenario.js';
import { truthOf, type ModelProfile, type Role } from './sim.js';

/** Monday 12:00 UTC. */
const START = Date.parse('2026-10-26T12:00:00Z');
const PSEUDONYM_KEY = 'evaluation-key-evaluation-key-0123';
/** How long after the last event the harness lets containments run out. */
const AFTERMATH_SECONDS = 7200;
const MODEL_CALL_LIMIT = 10_000;

export interface Call {
  role: Role;
  actor: string;
  model: string;
  request: ModelRequest;
  /** The reply, or an empty string if the profile threw. */
  reply: string;
  failed: boolean;
}

export interface Submission {
  id: string;
  kind: ProposedAction['kind'];
  target: string;
  level: ProposedAction['level'];
  proposedBy: string;
  status: SubmitStatus;
  /** Seconds after the scenario began. */
  at: number;
}

export interface Applied {
  id: string;
  kind: ProposedAction['kind'];
  target: string;
  at: number;
}

export interface Reverted {
  id: string;
  /** Seconds after the scenario began. */
  at: number;
}

export interface Hit {
  eventId: string;
  ruleId: string;
  alert: 'sent' | 'duplicate' | 'flood';
}

export interface RunRecord {
  scenario: Scenario;
  profile: string;
  /** The containments that count as right, with client addresses written as the pseudonyms the system uses. */
  correct: Containment[];
  /** What the investigators were allowed to name, and the targets no proposal may name, in the same terms. */
  offered: CaseTarget[];
  forbidden: string[];
  hits: Hit[];
  cycles: CycleReport[];
  submissions: Submission[];
  /** Containments (level 3 and 4) that a control adapter was asked to apply. */
  applied: Applied[];
  reverted: Reverted[];
  notifications: Notification[];
  calls: Call[];
  /** The whole audit log as text, for checking that nothing sensitive reached it. */
  auditText: string;
  auditOk: boolean;
}

export interface HarnessOptions {
  /** Dogs on the panel. Default 3: a majority is 2. */
  panelSize?: number;
  /** Investigators, each looking at every case. Default 2. */
  investigators?: number;
  /** Whether tier 2 triage runs. Default true. */
  triage?: boolean;
  /** Models asked by triage, 1 to 3. Any one of them can escalate. Default 1. */
  triageModels?: number;
  /**
   * The family of each of the four models, in order. Default: four families.
   * Models of one family share blind spots, which is what the same-family
   * comparison needs.
   */
  families?: readonly [string, string, string, string];
  /**
   * How the panel is made. `planned` (default) uses the planner, which puts one
   * model of each family on the panel and refuses to make a panel of one
   * family. `in-order` seats the models in order whatever their families,
   * which is how a panel built by hand goes wrong.
   */
  panel?: 'planned' | 'in-order';
}

const MODEL_IDS = ['model-a', 'model-b', 'model-c', 'model-d'] as const;
const DEFAULT_FAMILIES = ['family-a', 'family-b', 'family-c', 'family-d'] as const;
const VIEWS = ['raw-logs', 'summaries', 'timeline'] as const;

const CONTAINMENT_KINDS: readonly ProposedAction['kind'][] = ['contain.rate-limit', 'contain.block-source', 'contain.quarantine-file', 'contain.isolate-service'];

/** What this deployment lets run without a person, and the kinds of containment it has controls for. */
const PRE_APPROVED = {
  'contain.quarantine-file': { maxTtlSeconds: 1800, targets: ['/var/www/html/*'] },
  'contain.block-source': { maxTtlSeconds: 1800, targets: ['ip_*', '198.51.100.*'] },
  'contain.rate-limit': { maxTtlSeconds: 1800, targets: ['shop-web:*'] },
} as const;

export async function runScenario(scenario: Scenario, profile: ModelProfile, options: HarnessOptions = {}): Promise<RunRecord> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dogs-eval-'));
  try {
    return await run(scenario, profile, options, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run(scenario: Scenario, profile: ModelProfile, options: HarnessOptions, dir: string): Promise<RunRecord> {
  let now = START;
  const clock = (): Date => new Date(now);
  const seconds = (): number => Math.round((now - START) / 1000);

  const masker = createMasker({ pseudonymKey: PSEUDONYM_KEY });
  // The pipeline replaces client addresses with pseudonyms, so containments aimed at a client name the pseudonym.
  const resolve = (value: string): string => (value.startsWith('ip:') ? masker.maskText(value.slice(3)).text : value);
  const correct: Containment[] = scenario.correct.map((containment) => ({ kind: containment.kind, target: resolve(containment.target) }));
  const targets: CaseTarget[] = scenario.targets.map((entry) => ({ target: resolve(entry.target), kinds: entry.kinds }));
  const truth = truthOf(scenario, correct);

  const families = options.families ?? DEFAULT_FAMILIES;
  const registry = createModelRegistry(
    MODEL_IDS.map((id, index) => ({
      id,
      provider: `provider-${id.slice(-1)}`,
      family: families[index] as string,
      tier: 'large' as const,
      endpoint: `https://${id}.llm.example.invalid/v1/chat`,
      handling: 'zero-retention' as const,
      maxInputChars: 24_000,
    })),
  );

  const calls: Call[] = [];
  const client = (role: Role, actor: string, modelId: string): ModelClient => ({
    model: registry.require(modelId),
    async complete(request) {
      if (calls.length >= MODEL_CALL_LIMIT) throw new Error('the harness model-call limit was reached');
      const record: Call = { role, actor, model: modelId, request, reply: '', failed: false };
      calls.push(record);
      try {
        record.reply = await profile.reply(role, request, { actor, model: modelId, family: registry.require(modelId).family }, truth);
        return record.reply;
      } catch (error) {
        record.failed = true;
        throw error;
      }
    },
  });

  const size = options.panelSize ?? 3;
  const members =
    options.panel === 'in-order'
      ? Array.from({ length: size }, (_, seat) => ({ id: `dog-${seat + 1}`, model: MODEL_IDS[seat % MODEL_IDS.length] as string, evidenceView: VIEWS[seat % VIEWS.length] as string }))
      : planPanel(registry, { size, views: [...VIEWS] });
  const policy = createGatePolicy({
    panel: members,
    preApproved: PRE_APPROVED,
    protectedTargets: ['guard-dog:*'],
    approvers: ['operator'],
  });

  const log = AuditLog.open(path.join(dir, 'audit.jsonl'), { clock });
  const applied: Applied[] = [];
  const reverted: Reverted[] = [];
  const control: ControlAdapter = {
    async apply(action) {
      if (CONTAINMENT_KINDS.includes(action.kind)) applied.push({ id: action.id, kind: action.kind, target: action.target, at: seconds() });
      return { handle: { id: action.id } };
    },
    async revert(_handle, info) {
      reverted.push({ id: info.actionId, at: seconds() });
    },
  };
  const notifications: Notification[] = [];
  const executor = new Executor({
    policy,
    log,
    adapters: {
      'observe.raise-sampling': control,
      'contain.rate-limit': control,
      'contain.block-source': control,
      'contain.quarantine-file': control,
      'contain.isolate-service': control,
    },
    notifier: { notify: (notification) => void notifications.push(notification) },
    clock,
  });

  const egress = registry.egressHosts(members.map((member) => member.model));
  const pipeline = new Pipeline({
    masker,
    executor,
    log,
    inventory: [],
    allowedSources: [],
    rulesConfig: {
      ...defaultRulesConfig,
      webRoots: ['/var/www/html'],
      allowedWriters: ['deploy'],
      egressAllowList: { 'shop-web': ['payments.example', '*.cdn.example'], '*': [] },
      guardDogEgress: [...egress],
    },
    clock,
  });

  const submissions: Submission[] = [];
  const recording = {
    ingestEvents: (raw: readonly unknown[]) => pipeline.ingestEvents(raw),
    async submit(raw: unknown) {
      const result = await pipeline.submit(raw);
      const action = raw as ProposedAction;
      submissions.push({ id: action.id, kind: action.kind, target: action.target, level: action.level, proposedBy: action.proposedBy, status: result.status, at: seconds() });
      return result;
    },
  };

  const dogs = members.map((member) => new ModelDog({ id: member.id, evidenceView: member.evidenceView, client: client('dog', member.id, member.model) }));
  const investigatorCount = options.investigators ?? 2;
  const investigators = MODEL_IDS.slice(0, investigatorCount).map(
    (modelId, index) => new Investigator({ id: `investigator-${index + 1}`, client: client('investigator', `investigator-${index + 1}`, modelId), maxTtlSeconds: 1800, log, clock }),
  );
  // Triage uses the models from the other end, so it shares the fewest with the investigators.
  const triageIds = [...MODEL_IDS].reverse().slice(0, options.triageModels ?? 1);
  const triage = options.triage === false ? undefined : new TriageDog({ clients: triageIds.map((modelId) => client('triage', `triage-${modelId}`, modelId)), log });

  const orchestrator = new Orchestrator({
    pipeline: recording,
    policy,
    panel: new Panel({ policy, dogs, log }),
    investigators,
    ...(triage === undefined ? {} : { triage }),
    targets: () => targets,
    views: {
      'raw-logs': rawView,
      summaries: summaryView,
      timeline: (c: Case) => timelineView(c),
    },
    log,
    clock,
  });

  const hits: Hit[] = [];
  const cycles: CycleReport[] = [];
  const byTime = new Map<number, Scenario['events']>();
  for (const event of scenario.events) byTime.set(event.at, [...(byTime.get(event.at) ?? []), event]);

  for (const at of [...byTime.keys()].sort((a, b) => a - b)) {
    now = START + at * 1000;
    await executor.tick();
    const batch = (byTime.get(at) ?? []).map((event) => ({
      id: event.id,
      ts: clock().toISOString(),
      layer: event.layer,
      service: event.service,
      kind: event.kind,
      attrs: event.attrs,
    }));
    const { events, response } = await orchestrator.process(batch);
    for (const flagged of events.flagged) hits.push({ eventId: flagged.hit.eventId, ruleId: flagged.hit.ruleId, alert: flagged.alert });
    if (response.incidents > 0) cycles.push(response);
  }

  now += AFTERMATH_SECONDS * 1000;
  await executor.tick();

  const verify = log.verify();
  return {
    scenario,
    profile: profile.id,
    correct,
    offered: targets,
    forbidden: (scenario.forbidden ?? []).map(resolve),
    hits,
    cycles,
    submissions,
    applied,
    reverted,
    notifications,
    calls,
    auditText: JSON.stringify(log.entries()),
    auditOk: verify.ok,
  };
}

/** What happened and when, without the detail of each event: the facts the rule pulled out, in order. */
function timelineView(c: Case): unknown {
  return c.evidence.map((entry, index) => {
    const content = typeof entry.content === 'object' && entry.content !== null ? (entry.content as Record<string, unknown>) : {};
    const event = typeof content['event'] === 'object' && content['event'] !== null ? (content['event'] as Record<string, unknown>) : {};
    return { step: index + 1, id: entry.id, ts: event['ts'], kind: event['kind'], rule: content['rule'], found: content['flagged'] };
  });
}
