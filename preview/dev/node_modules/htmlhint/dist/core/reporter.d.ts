import { Hint, Rule, Ruleset, DisabledRulesMap } from './types';
export default class Reporter {
    html: string;
    lines: string[];
    brLen: number;
    ruleset: Ruleset;
    messages: Hint[];
    private disabledRulesMap;
    constructor(html: string, ruleset: Ruleset, disabledRulesMap?: DisabledRulesMap);
    info(message: string, line: number, col: number, rule: Rule, raw: string): void;
    warn(message: string, line: number, col: number, rule: Rule, raw: string): void;
    error(message: string, line: number, col: number, rule: Rule, raw: string): void;
    private report;
}
//# sourceMappingURL=reporter.d.ts.map