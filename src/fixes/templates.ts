import { Finding, FixSuggestion } from '../types';

/**
 * Returns a templated fix for known rule families. Falls back to a generic
 * suggestion for anything unrecognized, so every finding gets *some* guidance
 * even before an LLM fallback is wired in.
 */
export function suggestFix(finding: Finding): FixSuggestion {
  if (finding.scanner === 'secrets') {
    return {
      ruleId: finding.ruleId,
      summary: 'A credential-shaped value was committed to the repo.',
      steps: [
        'Rotate/revoke the exposed credential immediately at the provider — assume it is compromised the moment it hits a public or shared repo.',
        'Remove it from the current code and load it from an environment variable or secret manager instead.',
        'Add the file (or a pattern for it) to .gitignore so it is not re-committed.',
        'If the secret is already in git history (not just the latest commit), purge it from history — see command below — since rotating the key alone does not remove it from old commits.',
      ],
      commands: [
        '# Purge a file from all git history (rewrites history — coordinate with your team first):',
        'git filter-repo --path <path/to/file> --invert-paths',
      ],
    };
  }

  if (finding.scanner === 'deps') {
    return {
      ruleId: finding.ruleId,
      summary: `A dependency has a known vulnerability (${finding.ruleId}).`,
      steps: [
        'Check if a patched version is available for the affected package.',
        'Upgrade the dependency and re-run your test suite.',
        'If no patch exists yet, check the advisory for a workaround or consider a temporary alternative package.',
      ],
      commands: [
        '# Node.js:',
        'npm audit fix',
        '# Python:',
        'pip install --upgrade <package-name>',
      ],
    };
  }

  // pattern-based findings: give rule-family-specific guidance where we recognize it,
  // otherwise a generic "review this" fallback.
  const id = finding.ruleId.toLowerCase();

  if (id.includes('sql') || id.includes('injection')) {
    return {
      ruleId: finding.ruleId,
      summary: 'Possible SQL injection — user input may be concatenated directly into a query.',
      steps: [
        'Use parameterized queries / prepared statements instead of string concatenation.',
        'If using an ORM, confirm the query builder method used escapes input by default (some "raw" methods do not).',
      ],
    };
  }

  if (id.includes('eval') || id.includes('exec')) {
    return {
      ruleId: finding.ruleId,
      summary: 'Dynamic code execution on potentially untrusted input.',
      steps: [
        'Avoid eval()/exec()-style functions on any input that could be user-influenced.',
        'Replace with an explicit parser, allow-list, or safer language feature for the specific use case.',
      ],
    };
  }

  if (id.includes('crypto') || id.includes('hash') || id.includes('md5') || id.includes('sha1')) {
    return {
      ruleId: finding.ruleId,
      summary: 'Weak or outdated cryptographic primitive in use.',
      steps: [
        'Replace MD5/SHA1 with SHA-256 or better for integrity checks.',
        'For password storage specifically, use a purpose-built algorithm (bcrypt, scrypt, or argon2), not a general-purpose hash.',
      ],
    };
  }

  return {
    ruleId: finding.ruleId,
    summary: 'Unsafe pattern flagged by static analysis.',
    steps: [
      'Review the flagged line in context — semgrep rule descriptions (linked in the PR comment) explain the specific risk.',
      'If this is a confirmed false positive, add an inline `// nosemgrep: <rule-id>` comment with a brief reason.',
    ],
  };
}
