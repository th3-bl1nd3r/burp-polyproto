package burp.polyproto.rule;

import burp.polyproto.core.Direction;
import burp.polyproto.core.Msg;

/** One rule: a matcher plus an action. Higher {@link #priority} wins; ties broken by document order. */
public final class Rule {
    public String id;
    public String name;
    public boolean enabled = true;
    public int priority = 100;
    public Direction direction = Direction.BOTH;
    public Match match = new Match();
    public Action action = new Action();

    public boolean matches(Msg m) {
        if (!enabled) return false;
        if (direction != null && !direction.covers(m.direction())) return false;
        return match == null || match.matches(m);
    }
}
