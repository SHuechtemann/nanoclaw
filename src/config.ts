import os from 'os';
import path from 'path';

import { readEnvFile } from './env.js';
import { getContainerImageBase, getDefaultContainerImage, getInstallSlug } from './install-slug.js';
import { isValidTimezone } from './timezone.js';

// Read config values from .env (falls back to process.env).
const envConfig = readEnvFile([
  'ASSISTANT_NAME',
  'ASSISTANT_HAS_OWN_NUMBER',
  'ONECLI_URL',
  'ONECLI_API_KEY',
  'TZ',
  'WEB_PORT',
  'WEB_TOKEN',
  'WEB_MFA_SECRET',
  'DEFAULT_AGENT_PROVIDER',
  'CONTAINER_CPU_LIMIT',
  'CONTAINER_MEMORY_LIMIT',
  'NANOCLAW_EGRESS_LOCKDOWN',
  'NANOCLAW_EGRESS_NETWORK',
  'ONECLI_GATEWAY_CONTAINER',
]);

/**
 * @deprecated WhatsApp adapter copies now read the ASSISTANT_NAME .env key
 * directly. Re-export retained one release for stale adapter copies
 * (origin/channels whatsapp.ts:42 imports it); scheduled for deletion.
 */
export const ASSISTANT_NAME = process.env.ASSISTANT_NAME || envConfig.ASSISTANT_NAME || 'Andy';

// Instance-wide default agent provider for newly created groups. `claude` (the
// built-in provider) when unset, so existing installs are unaffected on upgrade.
// Applied only at group-creation time (stamped onto the config row) — never in
// provider resolution — so existing groups are never retroactively flipped.
// Per-group `ncl groups config update --provider` still overrides it.
export const DEFAULT_AGENT_PROVIDER = (
  process.env.DEFAULT_AGENT_PROVIDER ||
  envConfig.DEFAULT_AGENT_PROVIDER ||
  'claude'
).toLowerCase();

/**
 * @deprecated WhatsApp adapter copies now read the ASSISTANT_HAS_OWN_NUMBER
 * .env key directly. Re-export retained one release for stale adapter copies
 * (origin/channels whatsapp.ts:42 imports it); scheduled for deletion.
 */
export const ASSISTANT_HAS_OWN_NUMBER =
  (process.env.ASSISTANT_HAS_OWN_NUMBER || envConfig.ASSISTANT_HAS_OWN_NUMBER) === 'true';

// Absolute paths needed for container mounts
const PROJECT_ROOT = process.cwd();
const HOME_DIR = process.env.HOME || os.homedir();

// Mount security: allowlist stored OUTSIDE project root, never mounted into containers
export const MOUNT_ALLOWLIST_PATH = path.join(HOME_DIR, '.config', 'nanoclaw', 'mount-allowlist.json');
export const SENDER_ALLOWLIST_PATH = path.join(HOME_DIR, '.config', 'nanoclaw', 'sender-allowlist.json');
export const STORE_DIR = path.resolve(PROJECT_ROOT, 'store');
export const GROUPS_DIR = path.resolve(PROJECT_ROOT, 'groups');
export const DATA_DIR = path.resolve(PROJECT_ROOT, 'data');
// Local agent-template library. Committed but ships empty (+ README). Resolved
// once at load. Override to another LOCAL path via NANOCLAW_TEMPLATES_DIR; never
// a remote URL, never an ncl flag, never runtime-mutable.
export const TEMPLATES_DIR = process.env.NANOCLAW_TEMPLATES_DIR
  ? path.resolve(process.env.NANOCLAW_TEMPLATES_DIR)
  : path.resolve(PROJECT_ROOT, 'templates');

// Per-checkout image tag so two installs on the same host don't share
// `nanoclaw-agent:latest` and clobber each other on rebuild.
export const CONTAINER_IMAGE_BASE = process.env.CONTAINER_IMAGE_BASE || getContainerImageBase(PROJECT_ROOT);
export const CONTAINER_IMAGE = process.env.CONTAINER_IMAGE || getDefaultContainerImage(PROJECT_ROOT);
// Install slug — stamped onto every spawned container via --label so
// cleanupOrphans only reaps containers from this install, not peers.
export const INSTALL_SLUG = getInstallSlug(PROJECT_ROOT);
export const CONTAINER_INSTALL_LABEL = `nanoclaw-install=${INSTALL_SLUG}`;
export const ONECLI_URL = process.env.ONECLI_URL || envConfig.ONECLI_URL;
export const ONECLI_API_KEY = process.env.ONECLI_API_KEY || envConfig.ONECLI_API_KEY;
export const CONTAINER_CPU_LIMIT = process.env.CONTAINER_CPU_LIMIT || envConfig.CONTAINER_CPU_LIMIT || '';
export const CONTAINER_MEMORY_LIMIT = process.env.CONTAINER_MEMORY_LIMIT || envConfig.CONTAINER_MEMORY_LIMIT || '';

export const EGRESS_LOCKDOWN = (process.env.NANOCLAW_EGRESS_LOCKDOWN || envConfig.NANOCLAW_EGRESS_LOCKDOWN) === 'true';
export const EGRESS_NETWORK =
  process.env.NANOCLAW_EGRESS_NETWORK || envConfig.NANOCLAW_EGRESS_NETWORK || 'nanoclaw-egress';
export const ONECLI_GATEWAY_CONTAINER =
  process.env.ONECLI_GATEWAY_CONTAINER || envConfig.ONECLI_GATEWAY_CONTAINER || 'onecli';

// Web frontend
export const WEB_PORT = parseInt(process.env.WEB_PORT || envConfig.WEB_PORT || '18789', 10);
export const WEB_TOKEN = process.env.WEB_TOKEN || envConfig.WEB_TOKEN || '';
export const WEB_MFA_SECRET = process.env.WEB_MFA_SECRET || envConfig.WEB_MFA_SECRET || '';

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function buildTriggerPattern(trigger: string): RegExp {
  return new RegExp(`^${escapeRegex(trigger.trim())}\\b`, 'i');
}

export const DEFAULT_TRIGGER = `@${ASSISTANT_NAME}`;

export function getTriggerPattern(trigger?: string): RegExp {
  return buildTriggerPattern(trigger?.trim() || DEFAULT_TRIGGER);
}

export function getGroupTriggerPattern(trigger?: string): RegExp {
  const t = trigger?.trim() || DEFAULT_TRIGGER;
  return new RegExp(escapeRegex(t) + '\\b', 'i');
}

export const TRIGGER_PATTERN = buildTriggerPattern(DEFAULT_TRIGGER);

// Timezone for scheduled tasks, message formatting, etc.
// Validates each candidate is a real IANA identifier before accepting.
function resolveConfigTimezone(): string {
  const candidates = [process.env.TZ, envConfig.TZ, Intl.DateTimeFormat().resolvedOptions().timeZone];
  for (const tz of candidates) {
    if (tz && isValidTimezone(tz)) return tz;
  }
  return 'UTC';
}
export const TIMEZONE = resolveConfigTimezone();
