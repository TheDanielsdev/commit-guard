import { Finding, FixSuggestion } from '../types';

/**
 * Optional: if ANTHROPIC_API_KEY is available as a secret in the workflow,
 * this can generate a more specific fix suggestion for findings that the
 * static templates handle only generically. Not called by default — wire it
 * in from index.ts if you want this behavior.
 *
 * Kept deliberately dependency-free (plain fetch) so it doesn't bloat the
 * bundled Action.
 */
export async function suggestFixWithLLM(finding: Finding, apiKey: string): Promise<FixSuggestion | null> {
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 400,
        messages: [
          {
            role: 'user',
            content: `A static analysis tool flagged this finding in a code review bot:
Rule: ${finding.ruleId}
File: ${finding.file}${finding.line ? `:${finding.line}` : ''}
Message: ${finding.message}
${finding.snippet ? `Snippet: ${finding.snippet}` : ''}

Respond ONLY with JSON, no markdown fences, no preamble:
{"summary": "one sentence", "steps": ["step 1", "step 2"]}`,
          },
        ],
      }),
    });

    const data = (await res.json()) as { content?: { type: string; text?: string }[] };
    const text = data.content?.find((b) => b.type === 'text')?.text ?? '';
    const cleaned = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(cleaned);

    return {
      ruleId: finding.ruleId,
      summary: parsed.summary,
      steps: parsed.steps ?? [],
    };
  } catch {
    return null; // fall back to templates silently — never let this block the report
  }
}
