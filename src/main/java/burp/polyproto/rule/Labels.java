package burp.polyproto.rule;

import burp.polyproto.core.Msg;
import burp.polyproto.util.Json;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Extracts a short display label from a message per a {@link LabelSpec}, filling its template. */
public final class Labels {

    @SuppressWarnings("unchecked")
    public static String extract(LabelSpec s, Msg msg, String decodedText) {
        if (s == null || s.from == null) return null;
        Map<String, String> vars = new HashMap<>();
        String value = null;
        switch (s.from) {
            case "header":
                value = s.key == null ? null : msg.header(s.key);
                break;
            case "path-regex": {
                String p = msg.path() == null ? "" : msg.path();
                if (s.pattern != null) {
                    try {
                        Matcher m = Pattern.compile(s.pattern).matcher(p);
                        if (m.find()) {
                            value = m.group(0);
                            for (int i = 1; i <= m.groupCount(); i++)
                                vars.put(String.valueOf(i), m.group(i) == null ? "" : m.group(i));
                        }
                    } catch (Exception ignore) { }
                }
                break;
            }
            case "form-json-field": {
                try {
                    Object o = Json.parse(decodedText);
                    if (o instanceof Map) {
                        Map<String, Object> mm = (Map<String, Object>) o;
                        if (s.key != null && mm.get(s.key) != null) value = flat(mm.get(s.key));
                        if (s.alsoExtract != null)
                            for (String k : s.alsoExtract)
                                if (mm.get(k) != null) vars.put(k, flat(mm.get(k)));
                    }
                } catch (Exception ignore) { }
                break;
            }
            default:
                return null; // proto-field / envelope-field handled by packs later
        }
        if (value != null) vars.put("value", value);
        return apply(s.template != null ? s.template : "{value}", vars);
    }

    private static String apply(String tmpl, Map<String, String> vars) {
        String out = tmpl;
        for (Map.Entry<String, String> e : vars.entrySet()) out = out.replace("{" + e.getKey() + "}", e.getValue());
        out = out.replaceAll("\\{[^}]*\\}", "").trim();
        return out.isEmpty() ? null : out;
    }

    private static String flat(Object o) {
        return (o instanceof Map || o instanceof List) ? Json.emit(o) : String.valueOf(o);
    }

    private Labels() {}
}
