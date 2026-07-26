package burp.polyproto.rule;

import burp.polyproto.core.Direction;
import burp.polyproto.core.Msg;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * The live, shared rule set. A single immutable snapshot is swapped atomically on edit, so lookups
 * are lock-free. Editors and the HTTP handler both read from the singleton.
 */
public final class RuleRegistry {
    private static final RuleRegistry INSTANCE = new RuleRegistry();
    public static RuleRegistry get() { return INSTANCE; }

    private volatile List<Rule> rules = List.of();

    private RuleRegistry() {}

    /** Replace the rule set (sorted by priority desc, stable for ties = document order). */
    public void set(List<Rule> rs) {
        List<Rule> copy = new ArrayList<>(rs);
        copy.sort(Comparator.comparingInt((Rule r) -> r.priority).reversed());
        this.rules = Collections.unmodifiableList(copy);
    }

    public List<Rule> snapshot() { return rules; }

    /** First enabled rule (priority desc) whose matcher matches, or null. */
    public Rule firstMatch(Msg m) {
        for (Rule r : rules) {
            try {
                if (r.matches(m)) return r;
            } catch (Exception ignore) { /* a broken rule never blocks the rest */ }
        }
        return null;
    }

    /** Union of header rewrites from ALL matching enabled rules applicable to the message direction. */
    public List<HeaderRewrite> requestRewrites(Msg m) {
        List<HeaderRewrite> out = new ArrayList<>();
        for (Rule r : rules) {
            try {
                if (!r.matches(m)) continue;
                if (r.action == null || r.action.rewriteHeader == null) continue;
                for (HeaderRewrite hr : r.action.rewriteHeader) {
                    Direction to = hr.applyTo == null ? Direction.REQUEST : hr.applyTo;
                    if (to.covers(m.direction())) out.add(hr);
                }
            } catch (Exception ignore) { }
        }
        return out;
    }
}
