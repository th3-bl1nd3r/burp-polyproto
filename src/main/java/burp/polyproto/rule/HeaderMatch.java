package burp.polyproto.rule;

import burp.polyproto.core.Msg;

import java.util.regex.Pattern;

/** Matches a single header by name; {@code valueRegex} null/empty = presence only. */
public final class HeaderMatch {
    public String name;
    public String valueRegex;
    private transient Pattern re;

    public boolean matches(Msg m) {
        if (name == null) return false;
        String v = m.header(name);
        if (v == null) return false;
        if (valueRegex == null || valueRegex.isEmpty()) return true;
        try {
            if (re == null) re = Pattern.compile(valueRegex);
            return re.matcher(v).find();
        } catch (Exception e) {
            return false;
        }
    }
}
