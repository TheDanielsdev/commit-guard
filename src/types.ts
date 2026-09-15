export type Severity = 'high' | 'medium' | 'low';

export type ScannerName = 'secrets' | 'deps' | 'patterns';

export interface Finding {
  scanner: ScannerName;
  ruleId: string;
  severity: Severity;
  file: string;
  line?: number;
  message: string;
  /** Raw snippet if safe to show (secrets scanner should redact this) */
  snippet?: string;
}

export interface FixSuggestion {
  ruleId: string;
  summary: string;
  steps: string[];
  /** Optional shell command(s) the user can copy-paste */
  commands?: string[];
}

export interface ScanResult {
  findings: Finding[];
}
