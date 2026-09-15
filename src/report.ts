import { Finding, FixSuggestion, Severity } from './types';

const SEVERITY_EMOJI: Record<Severity, string> = {
  high: '🔴',
  medium: '🟠',
  low: '🟡',
};

export function buildMarkdownReport(findings: Finding[], fixes: Map<string, FixSuggestion>): string {
  if (findings.length === 0) {
    return '### 🛡️ Commit Guard\n\nNo issues found. ✅';
  }

  const bySeverity = { high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  for (const f of findings) bySeverity[f.severity]++;

  const lines: string[] = [];
  lines.push('### 🛡️ Commit Guard');
  lines.push('');
  lines.push(
    `Found **${findings.length}** issue(s): ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low.`
  );
  lines.push('');

  const grouped = groupBy(findings, (f) => f.scanner);

  for (const [scanner, group] of Object.entries(grouped)) {
    lines.push(`#### ${scannerTitle(scanner)}`);
    lines.push('');
    for (const finding of group) {
      const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      lines.push(`- ${SEVERITY_EMOJI[finding.severity]} **${finding.ruleId}** — \`${loc}\``);
      lines.push(`  ${finding.message}`);

      const fix = fixes.get(fixKey(finding));
      if (fix) {
        lines.push(`  <details><summary>Suggested fix</summary>`);
        lines.push('');
        lines.push(`  ${fix.summary}`);
        lines.push('');
        for (const step of fix.steps) {
          lines.push(`  - ${step}`);
        }
        if (fix.commands?.length) {
          lines.push('');
          lines.push('  ```bash');
          for (const cmd of fix.commands) lines.push(`  ${cmd}`);
          lines.push('  ```');
        }
        lines.push(`  </details>`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

export function fixKey(finding: Finding): string {
  return `${finding.scanner}:${finding.ruleId}:${finding.file}:${finding.line ?? ''}`;
}

function scannerTitle(scanner: string): string {
  switch (scanner) {
    case 'secrets':
      return '🔑 Secrets';
    case 'deps':
      return '📦 Dependency vulnerabilities';
    case 'patterns':
      return '⚠️ Unsafe code patterns';
    default:
      return scanner;
  }
}

function groupBy<T, K extends string>(items: T[], keyFn: (item: T) => K): Record<K, T[]> {
  const result = {} as Record<K, T[]>;
  for (const item of items) {
    const key = keyFn(item);
    (result[key] ??= []).push(item);
  }
  return result;
}
