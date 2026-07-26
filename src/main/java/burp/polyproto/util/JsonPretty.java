package burp.polyproto.util;

/** Minimal dependency-free JSON pretty-printer. Best-effort: if input isn't JSON, returns it unchanged. */
public final class JsonPretty {

    public static String pretty(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.isEmpty() || (t.charAt(0) != '{' && t.charAt(0) != '[')) return s;
        StringBuilder out = new StringBuilder(s.length() + 64);
        int indent = 0;
        boolean inStr = false, esc = false;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (inStr) {
                out.append(c);
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            switch (c) {
                case '"': inStr = true; out.append(c); break;
                case '{': case '[':
                    out.append(c);
                    if (!nextIsClose(t, i, c)) { out.append('\n'); indent++; pad(out, indent); }
                    break;
                case '}': case ']':
                    if (!prevIsOpen(out)) { out.append('\n'); indent = Math.max(0, indent - 1); pad(out, indent); }
                    else { indent = Math.max(0, indent - 1); }
                    out.append(c);
                    break;
                case ',':
                    out.append(c).append('\n'); pad(out, indent);
                    break;
                case ':':
                    out.append(": ");
                    break;
                case ' ': case '\n': case '\r': case '\t':
                    break; // collapse existing whitespace
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    private static boolean nextIsClose(String t, int i, char open) {
        char close = open == '{' ? '}' : ']';
        for (int j = i + 1; j < t.length(); j++) {
            char c = t.charAt(j);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
            return c == close;
        }
        return false;
    }

    private static boolean prevIsOpen(StringBuilder out) {
        for (int j = out.length() - 1; j >= 0; j--) {
            char c = out.charAt(j);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
            return c == '{' || c == '[';
        }
        return false;
    }

    private static void pad(StringBuilder sb, int indent) {
        for (int i = 0; i < indent; i++) sb.append("  ");
    }

    private JsonPretty() {}
}
