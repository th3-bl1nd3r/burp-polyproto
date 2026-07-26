package burp.polyproto.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny dependency-free JSON: a recursive-descent parser and an emitter over native Java values
 * (LinkedHashMap / ArrayList / String / Long / Double / Boolean / null). Order-preserving so
 * round-trips are stable diffs. Used by the Meta {@code form+json} stage and the rule codec, which
 * lets us drop Gson.
 */
public final class Json {

    // ---- parse ----

    public static Object parse(String s) {
        Parser p = new Parser(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.pos != s.length()) throw new IllegalArgumentException("trailing content at " + p.pos);
        return v;
    }

    /** Convenience: parse and cast to an object, or throw. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String s) {
        Object v = parse(s);
        if (!(v instanceof Map)) throw new IllegalArgumentException("not a JSON object");
        return (Map<String, Object>) v;
    }

    private static final class Parser {
        final String s;
        int pos;
        Parser(String s) { this.s = s; }

        void ws() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object value() {
            if (pos >= s.length()) throw err("unexpected end");
            char c = s.charAt(pos);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default:  return number();
            }
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; // {
            ws();
            if (peek() == '}') { pos++; return m; }
            while (true) {
                ws();
                if (peek() != '"') throw err("expected key string");
                String k = string();
                ws();
                if (peek() != ':') throw err("expected ':'");
                pos++;
                ws();
                m.put(k, value());
                ws();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; break; }
                throw err("expected ',' or '}'");
            }
            return m;
        }

        List<Object> array() {
            List<Object> a = new ArrayList<>();
            pos++; // [
            ws();
            if (peek() == ']') { pos++; return a; }
            while (true) {
                ws();
                a.add(value());
                ws();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; break; }
                throw err("expected ',' or ']'");
            }
            return a;
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            pos++; // opening "
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= s.length()) break;
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            pos += 4;
                            break;
                        default: throw err("bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw err("unterminated string");
        }

        Object number() {
            int start = pos;
            boolean dbl = false;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == '-' || c == '+' || (c >= '0' && c <= '9')) { pos++; }
                else if (c == '.' || c == 'e' || c == 'E') { dbl = true; pos++; }
                else break;
            }
            String n = s.substring(start, pos);
            if (n.isEmpty()) throw err("invalid number");
            if (dbl) return Double.parseDouble(n);
            try { return Long.parseLong(n); }
            catch (NumberFormatException ex) { return Double.parseDouble(n); }
        }

        char peek() { return pos < s.length() ? s.charAt(pos) : '\0'; }

        void expect(String lit) {
            if (!s.startsWith(lit, pos)) throw err("expected " + lit);
            pos += lit.length();
        }

        IllegalArgumentException err(String msg) {
            return new IllegalArgumentException("JSON parse: " + msg + " at " + pos);
        }
    }

    // ---- emit ----

    public static String emit(Object v) {
        StringBuilder sb = new StringBuilder();
        write(v, sb, -1, 0);
        return sb.toString();
    }

    public static String pretty(Object v) {
        StringBuilder sb = new StringBuilder();
        write(v, sb, 2, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(Object v, StringBuilder sb, int indent, int depth) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String) { quote((String) v, sb); return; }
        if (v instanceof Boolean || v instanceof Number) { sb.append(v.toString()); return; }
        boolean pretty = indent >= 0;
        String nl = pretty ? "\n" : "";
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            if (m.isEmpty()) { sb.append("{}"); return; }
            sb.append('{').append(nl);
            int i = 0;
            for (Map.Entry<String, Object> e : m.entrySet()) {
                pad(sb, indent, depth + 1);
                quote(e.getKey(), sb);
                sb.append(pretty ? ": " : ":");
                write(e.getValue(), sb, indent, depth + 1);
                if (++i < m.size()) sb.append(',');
                sb.append(nl);
            }
            pad(sb, indent, depth);
            sb.append('}');
        } else if (v instanceof List) {
            List<Object> a = (List<Object>) v;
            if (a.isEmpty()) { sb.append("[]"); return; }
            sb.append('[').append(nl);
            for (int i = 0; i < a.size(); i++) {
                pad(sb, indent, depth + 1);
                write(a.get(i), sb, indent, depth + 1);
                if (i + 1 < a.size()) sb.append(',');
                sb.append(nl);
            }
            pad(sb, indent, depth);
            sb.append(']');
        } else {
            quote(String.valueOf(v), sb);
        }
    }

    private static void pad(StringBuilder sb, int indent, int depth) {
        if (indent < 0) return;
        for (int i = 0; i < indent * depth; i++) sb.append(' ');
    }

    private static void quote(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    private Json() {}
}
