import * as exec from '@actions/exec';
import * as core from '@actions/core';
import * as fs from 'fs';
import { Finding, Severity } from '../types';

/**
 * Runs osv-scanner against the repo's manifest/lockfiles.
 * Requires the `osv-scanner` binary on PATH.
 */
export async function scanDependencies(): Promise<Finding[]> {
  const reportPath = '/tmp/osv-report.json';
  const args = ['--format', 'json', '--output', reportPath, '.', '--recursive'];

  try {
    // osv-scanner exits non-zero when vulns are found — that's expected, don't throw
    await exec.exec('osv-scanner', args, { ignoreReturnCode: true });
  } catch (err) {
    core.warning(`osv-scanner execution failed: ${(err as Error).message}`);
    return [];
  }

  if (!fs.existsSync(reportPath)) return [];

  const raw = fs.readFileSync(reportPath, 'utf-8').trim();
  if (!raw) return [];

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    core.warning('Could not parse osv-scanner report as JSON');
    return [];
  }

  const findings: Finding[] = [];

  for (const result of parsed.results ?? []) {
    const source = result.source?.path ?? 'unknown manifest';
    for (const pkg of result.packages ?? []) {
      const pkgName = pkg.package?.name ?? 'unknown package';
      const pkgVersion = pkg.package?.version ?? '';
      for (const vuln of pkg.vulnerabilities ?? []) {
        findings.push({
          scanner: 'deps',
          ruleId: vuln.id ?? 'unknown-cve',
          severity: mapSeverity(vuln.severity),
          file: source,
          message: `${pkgName}@${pkgVersion} is affected by ${vuln.id}: ${truncate(vuln.summary ?? 'no summary provided', 160)}`,
        });
      }
    }
  }

  return findings;
}

function mapSeverity(severityBlocks: any[] | undefined): Severity {
  if (!severityBlocks || severityBlocks.length === 0) return 'medium';
  const score = parseFloat(severityBlocks[0]?.score?.split('/')[0] ?? '0');
  if (score >= 9) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
