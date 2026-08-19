export interface InjectionRule {
  readonly id: string;
  readonly locale: string;
  readonly category: string;
  readonly pattern: string;
  readonly flags: "i" | "";
  readonly weight: number;
}

export interface InjectionMatch {
  readonly ruleId: string;
  readonly category: string;
  readonly evidence: string;
}

/** English rule pack (OAF-BROWSER-010). Rules are inert data, never executable code. */
export const ENGLISH_RULES: readonly InjectionRule[] = [
  {
    id: "override_instructions",
    locale: "en",
    category: "instruction_override",
    pattern:
      "ignore (all |any )?(previous|prior|above|earlier|original) (instructions?|prompts?|rules?)",
    flags: "i",
    weight: 3,
  },
  {
    id: "disregard_system",
    locale: "en",
    category: "instruction_override",
    pattern: "(disregard|forget|override) (everything|all) (you|you've) (been|were) (told|asked)",
    flags: "i",
    weight: 3,
  },
  {
    id: "claim_system_message",
    locale: "en",
    category: "system_message_claim",
    pattern:
      "(you are|this is) (now )?(an? )?(unfiltered|uncensored|jailbroken|new|different) (ai|assistant|model|mode)",
    flags: "i",
    weight: 2,
  },
  {
    id: "reveal_prompt",
    locale: "en",
    category: "prompt_extraction",
    pattern:
      "(reveal|repeat|print|show|recite|output) (me )?(your |the )?(system |developer )?(prompt|instructions?|rules?)",
    flags: "i",
    weight: 3,
  },
  {
    id: "reveal_credentials",
    locale: "en",
    category: "credential_extraction",
    pattern:
      "(reveal|send|share|exfiltrate) (your |the )?(credentials?|passwords?|api[ _-]?keys?|tokens?|cookies?)",
    flags: "i",
    weight: 3,
  },
  {
    id: "forced_navigation",
    locale: "en",
    category: "forced_navigation",
    pattern:
      "(go to|navigate to|open|visit|browse to) (the )?(url|site|page|link)?\\s*https?:\\/\\/",
    flags: "i",
    weight: 2,
  },
  {
    id: "external_contact",
    locale: "en",
    category: "external_contact",
    pattern:
      "(send|email|message|forward|upload) (this|the) (data|information|report|content|result)",
    flags: "i",
    weight: 2,
  },
  {
    id: "disable_security",
    locale: "en",
    category: "security_bypass",
    pattern:
      "(disable|turn off|ignore|bypass|skip) (the |all )?(security|safety|filters?|guardrails?|protections?)",
    flags: "i",
    weight: 3,
  },
  {
    id: "addressed_to_agent",
    locale: "en",
    category: "agent_addressed",
    pattern:
      "\\b(hey|hi|dear|attention|hello)\\b[^.]{0,30}\\b(ai|assistant|agent|chatgpt|gpt|claude|llm|gemini)\\b",
    flags: "i",
    weight: 1,
  },
];

/** Scan text for injection-pattern matches, returning redacted-evidence excerpts. */
export function scanInjection(
  text: string,
  rules: readonly InjectionRule[] = ENGLISH_RULES,
): InjectionMatch[] {
  const matches: InjectionMatch[] = [];
  for (const rule of rules) {
    const pattern = compileRule(rule);
    if (pattern === null) {
      continue;
    }
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null && matches.length < 50) {
      const start = Math.max(0, m.index - 40);
      const end = Math.min(text.length, m.index + m[0].length + 40);
      matches.push({
        ruleId: rule.id,
        category: rule.category,
        evidence: text.slice(start, end),
      });
      if (m[0].length === 0) {
        pattern.lastIndex += 1;
      }
    }
  }
  return matches;
}

/** Rejects executable/non-linear rule-pack shapes before a regex is compiled. */
export function validateRulePack(rules: readonly InjectionRule[]): boolean {
  return rules.length <= 100 && rules.every((rule) => compileRule(rule) !== null);
}

function compileRule(rule: InjectionRule): RegExp | null {
  if (
    !/^[a-z0-9_-]{1,64}$/i.test(rule.id) ||
    !/^[a-z]{2,16}$/i.test(rule.locale) ||
    !/^[a-z0-9_-]{1,64}$/i.test(rule.category) ||
    rule.pattern.length === 0 ||
    rule.pattern.length > 512 ||
    rule.weight < 0 ||
    rule.weight > 10 ||
    /\(\?[:=!<]/.test(rule.pattern) ||
    /\([^)]*[+*][^)]*\)[+*{]/.test(rule.pattern) ||
    /(?:\*|\+|\{\d+(?:,\d*)?\})\s*(?:\*|\+|\{)/.test(rule.pattern)
  ) {
    return null;
  }
  try {
    return new RegExp(rule.pattern, `${rule.flags}g`);
  } catch {
    return null;
  }
}
