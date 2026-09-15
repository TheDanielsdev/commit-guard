import * as core from '@actions/core';
import * as github from '@actions/github';
import { scanSecrets } from './scanners/secrets';
import { scanDependencies } from './scanners/deps';
import { scanPatterns } from './scanners/patterns';
import { suggestFix } from './fixes/templates';
import { buildMarkdownReport, fixKey } from './report';
import { Finding, Severity } from './types';

const SEVERITY_RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

async function run(): Promise<void> {
  try {
    const token = core.getInput('github-token');
    const failOn = (core.getInput('fail-on') || 'high') as Severity | 'none';
    const commentOnPr = core.getBooleanInput('comment-on-pr');
    const runSecrets = core.getBooleanInput('enable-secrets-scan');
    const runDeps = core.getBooleanInput('enable-deps-scan');
    const runPatterns = core.getBooleanInput('enable-pattern-scan');

    const context = github.context;
    const baseRef = context.payload.pull_request?.base?.sha ?? `${context.sha}~1`;
    const headRef = context.sha;

    const allFindings: Finding[] = [];

    if (runSecrets) {
      core.info('Running secrets scan (gitleaks)...');
      allFindings.push(...(await scanSecrets(baseRef, headRef)));
    }

    if (runDeps) {
      core.info('Running dependency scan (osv-scanner)...');
      allFindings.push(...(await scanDependencies()));
    }

    if (runPatterns) {
      core.info('Running pattern scan (semgrep)...');
      allFindings.push(...(await scanPatterns()));
    }

    core.setOutput('findings-count', String(allFindings.length));
    core.setOutput(
      'high-severity-count',
      String(allFindings.filter((f) => f.severity === 'high').length)
    );

    const fixes = new Map();
    for (const finding of allFindings) {
      fixes.set(fixKey(finding), suggestFix(finding));
    }

    const report = buildMarkdownReport(allFindings, fixes);
    await core.summary.addRaw(report).write();

    if (commentOnPr && context.payload.pull_request) {
      const octokit = github.getOctokit(token);
      await octokit.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.payload.pull_request.number,
        body: report,
      });
    } else {
      core.info(report);
    }

    if (failOn !== 'none') {
      const threshold = SEVERITY_RANK[failOn as Severity];
      const shouldFail = allFindings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
      if (shouldFail) {
        core.setFailed(
          `Commit Guard found ${allFindings.length} issue(s) at or above "${failOn}" severity.`
        );
      }
    }
  } catch (err) {
    core.setFailed(`Commit Guard failed unexpectedly: ${(err as Error).message}`);
  }
}

run();
