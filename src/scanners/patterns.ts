import * as exec from '@actions/exec';
import * as core from '@actions/core';
import * as fs from 'fs';
import { Finding, Severity } from '../types';

/**
 * Runs semgrep with the auto-config (community rules covering OWASP-style
 * issues: SQL injection, unsafe eval/deserialization, weak crypto, etc.)
 * Requires the `semgrep` binary on PATH.
 */
export async function scanPatterns(): Promise<Finding[]> {
  const reportPath = '/tmp/semgrep-report.json';
  const args = ['scan', '--config', 'auto', '--json', '--output', reportPath, '--quiet'];

  try {
    await exec.exec('semgrep', args, { ignoreReturnCode: true });
  } catch (err) {
    core.warning(`semgrep execution failed: ${(err as Error).message}`);
    return [];
  }

  if (!fs.existsSync(reportPath)) return [];

  const raw = fs.readFileSync(reportPath, 'utf-8').trim();
  if (!raw) return [];

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    core.warning('Could not parse semgrep report as JSON');
    return [];
  }

  return (parsed.results ?? []).map((r: any): Finding => ({
    scanner: 'patterns',
    ruleId: r.check_id ?? 'unknown-pattern',
    severity: mapSeverity(r.extra?.severity),
    file: r.path ?? 'unknown',
    line: r.start?.line,
    message: r.extra?.message ?? 'Unsafe code pattern detected.',
    snippet: r.extra?.lines,
  }));
}

function mapSeverity(sev: string | undefined): Severity {
  switch ((sev ?? '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    default:
      return 'low';
  }
}
