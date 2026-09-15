import * as exec from '@actions/exec';
import * as core from '@actions/core';
import * as fs from 'fs';
import { Finding } from '../types';

/**
 * Runs gitleaks against the repo's git history for the current push/PR range.
 * Requires the `gitleaks` binary to be present on PATH (installed as a
 * separate step in the workflow — see README).
 */
export async function scanSecrets(baseRef: string, headRef: string): Promise<Finding[]> {
  const reportPath = '/tmp/gitleaks-report.json';
  const args = [
    'detect',
    '--source', '.',
    '--report-format', 'json',
    '--report-path', reportPath,
    '--redact',
    '--no-banner',
    '--log-opts', `${baseRef}..${headRef}`,
    '--exit-code', '0', // never let gitleaks itself fail the step; we handle severity ourselves
  ];

  try {
    await exec.exec('gitleaks', args);
  } catch (err) {
    core.warning(`gitleaks execution failed: ${(err as Error).message}`);
    return [];
  }

  if (!fs.existsSync(reportPath)) {
    return [];
  }

  const raw = fs.readFileSync(reportPath, 'utf-8').trim();
  if (!raw) return [];

  let parsed: any[];
  try {
    parsed = JSON.parse(raw);
  } catch {
    core.warning('Could not parse gitleaks report as JSON');
    return [];
  }

  return parsed.map((item) => ({
    scanner: 'secrets' as const,
    ruleId: item.RuleID ?? 'unknown-secret',
    severity: 'high' as const, // any confirmed secret match is treated as high severity
    file: item.File ?? 'unknown',
    line: item.StartLine,
    message: `Potential secret detected (${item.RuleID}). Value has been redacted.`,
    // snippet intentionally omitted — never surface secret material even redacted
  }));
}
