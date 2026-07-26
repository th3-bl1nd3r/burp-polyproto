package burp.polyproto.rule;

import burp.polyproto.core.Direction;
import burp.polyproto.core.Transport;
import burp.polyproto.util.Json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Ruleset ⇄ JSON, mapping the dependency-free {@link Json} model onto the rule POJOs. */
public final class RuleCodec {

    // ---------- parse ----------

    @SuppressWarnings("unchecked")
    public static Ruleset fromJson(String jsonText) {
        Object root = Json.parse(jsonText);
        if (!(root instanceof Map)) throw new IllegalArgumentException("ruleset root must be a JSON object");
        Map<String, Object> m = (Map<String, Object>) root;
        Ruleset rs = new Ruleset();
        rs.version = (int) asLong(m.get("version"), 1);
        for (Object ro : asList(m.get("rules"))) rs.rules.add(rule((Map<String, Object>) ro));
        Object sp = m.get("schemaPacks");
        if (sp instanceof Map) rs.schemaPacks = (Map<String, Object>) sp;
        Object dict = m.get("dictionaries");
        if (dict instanceof Map) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) dict).entrySet())
                rs.dictionaries.put(e.getKey(), String.valueOf(e.getValue()));
        }
        return rs;
    }

    @SuppressWarnings("unchecked")
    private static Rule rule(Map<String, Object> m) {
        Rule r = new Rule();
        r.id = str(m.get("id"));
        r.name = str(m.get("name"));
        r.enabled = asBool(m.get("enabled"), true);
        r.priority = (int) asLong(m.get("priority"), 100);
        r.direction = dir(m.get("direction"), Direction.BOTH);
        if (m.get("match") instanceof Map) r.match = match((Map<String, Object>) m.get("match"));
        if (m.get("action") instanceof Map) r.action = action((Map<String, Object>) m.get("action"));
        return r;
    }

    @SuppressWarnings("unchecked")
    private static Match match(Map<String, Object> m) {
        Match x = new Match();
        String tr = str(m.get("transport"));
        if (tr != null) x.transport = Transport.valueOf(tr);
        x.hostsAny = strList(m.get("hostsAny"));
        x.pathRegex = str(m.get("pathRegex"));
        x.methods = strList(m.get("methods"));
        x.contentTypesAny = strList(m.get("contentTypesAny"));
        x.wsSubprotocol = str(m.get("wsSubprotocol"));
        x.headerNamePrefixAny = strList(m.get("headerNamePrefixAny"));
        for (Object ho : asList(m.get("headers"))) {
            Map<String, Object> hm = (Map<String, Object>) ho;
            HeaderMatch h = new HeaderMatch();
            h.name = str(hm.get("name"));
            h.valueRegex = str(hm.get("valueRegex"));
            (x.headers == null ? (x.headers = new ArrayList<>()) : x.headers).add(h);
        }
        for (Object so : asList(m.get("anyOf"))) {
            (x.anyOf == null ? (x.anyOf = new ArrayList<>()) : x.anyOf).add(match((Map<String, Object>) so));
        }
        return x;
    }

    @SuppressWarnings("unchecked")
    private static Action action(Map<String, Object> m) {
        Action a = new Action();
        a.forcePipeline = strList(m.get("forcePipeline"));
        a.encodingHeaders = strList(m.get("encodingHeaders"));
        a.perMessageCodecHeader = str(m.get("perMessageCodecHeader"));
        a.schemaPack = str(m.get("schemaPack"));
        a.schemaSelect = str(m.get("schemaSelect"));
        for (Object ro : asList(m.get("rewriteHeader"))) {
            Map<String, Object> hm = (Map<String, Object>) ro;
            HeaderRewrite h = new HeaderRewrite();
            h.name = str(hm.get("name"));
            h.setValue = str(hm.get("setValue"));
            h.onlyIfPresent = asBool(hm.get("onlyIfPresent"), false);
            h.ifValueContains = str(hm.get("ifValueContains"));
            h.remove = asBool(hm.get("remove"), false);
            h.applyTo = dir(hm.get("applyTo"), Direction.REQUEST);
            (a.rewriteHeader == null ? (a.rewriteHeader = new ArrayList<>()) : a.rewriteHeader).add(h);
        }
        if (m.get("recomputeSig") instanceof Map) {
            Map<String, Object> sm = (Map<String, Object>) m.get("recomputeSig");
            SigSpec s = new SigSpec();
            s.enabled = asBool(sm.get("enabled"), false);
            s.header = str(sm.get("header"));
            s.algo = str(sm.get("algo"));
            s.over = str(sm.get("over")) != null ? str(sm.get("over")) : "wire-body";
            s.addIfMissing = asBool(sm.get("addIfMissing"), true);
            a.recomputeSig = s;
        }
        if (m.get("label") instanceof Map) {
            Map<String, Object> lm = (Map<String, Object>) m.get("label");
            LabelSpec l = new LabelSpec();
            l.from = str(lm.get("from"));
            l.key = str(lm.get("key"));
            l.pattern = str(lm.get("pattern"));
            l.template = str(lm.get("template"));
            l.alsoExtract = strList(lm.get("alsoExtract"));
            a.label = l;
        }
        return a;
    }

    // ---------- emit ----------

    public static String toJson(Ruleset rs) { return Json.pretty(toMap(rs)); }

    public static Map<String, Object> toMap(Ruleset rs) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", (long) rs.version);
        List<Object> rules = new ArrayList<>();
        for (Rule r : rs.rules) rules.add(ruleMap(r));
        m.put("rules", rules);
        if (rs.schemaPacks != null && !rs.schemaPacks.isEmpty()) m.put("schemaPacks", rs.schemaPacks);
        if (rs.dictionaries != null && !rs.dictionaries.isEmpty()) m.put("dictionaries", rs.dictionaries);
        return m;
    }

    private static Map<String, Object> ruleMap(Rule r) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "id", r.id);
        put(m, "name", r.name);
        m.put("enabled", r.enabled);
        m.put("priority", (long) r.priority);
        if (r.direction != null && r.direction != Direction.BOTH) m.put("direction", r.direction.name());
        m.put("match", matchMap(r.match));
        m.put("action", actionMap(r.action));
        return m;
    }

    private static Map<String, Object> matchMap(Match x) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (x == null) return m;
        if (x.transport != null) m.put("transport", x.transport.name());
        putList(m, "hostsAny", x.hostsAny);
        put(m, "pathRegex", x.pathRegex);
        putList(m, "methods", x.methods);
        putList(m, "contentTypesAny", x.contentTypesAny);
        put(m, "wsSubprotocol", x.wsSubprotocol);
        putList(m, "headerNamePrefixAny", x.headerNamePrefixAny);
        if (x.headers != null && !x.headers.isEmpty()) {
            List<Object> hs = new ArrayList<>();
            for (HeaderMatch h : x.headers) {
                Map<String, Object> hm = new LinkedHashMap<>();
                put(hm, "name", h.name);
                put(hm, "valueRegex", h.valueRegex);
                hs.add(hm);
            }
            m.put("headers", hs);
        }
        if (x.anyOf != null && !x.anyOf.isEmpty()) {
            List<Object> ao = new ArrayList<>();
            for (Match sub : x.anyOf) ao.add(matchMap(sub));
            m.put("anyOf", ao);
        }
        return m;
    }

    private static Map<String, Object> actionMap(Action a) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (a == null) return m;
        putList(m, "forcePipeline", a.forcePipeline);
        putList(m, "encodingHeaders", a.encodingHeaders);
        put(m, "perMessageCodecHeader", a.perMessageCodecHeader);
        put(m, "schemaPack", a.schemaPack);
        put(m, "schemaSelect", a.schemaSelect);
        if (a.rewriteHeader != null && !a.rewriteHeader.isEmpty()) {
            List<Object> rs = new ArrayList<>();
            for (HeaderRewrite h : a.rewriteHeader) {
                Map<String, Object> hm = new LinkedHashMap<>();
                put(hm, "name", h.name);
                put(hm, "setValue", h.setValue);
                if (h.onlyIfPresent) hm.put("onlyIfPresent", true);
                put(hm, "ifValueContains", h.ifValueContains);
                if (h.remove) hm.put("remove", true);
                if (h.applyTo != null && h.applyTo != Direction.REQUEST) hm.put("applyTo", h.applyTo.name());
                rs.add(hm);
            }
            m.put("rewriteHeader", rs);
        }
        if (a.recomputeSig != null) {
            Map<String, Object> sm = new LinkedHashMap<>();
            sm.put("enabled", a.recomputeSig.enabled);
            put(sm, "header", a.recomputeSig.header);
            put(sm, "algo", a.recomputeSig.algo);
            put(sm, "over", a.recomputeSig.over);
            m.put("recomputeSig", sm);
        }
        if (a.label != null) {
            Map<String, Object> lm = new LinkedHashMap<>();
            put(lm, "from", a.label.from);
            put(lm, "key", a.label.key);
            put(lm, "pattern", a.label.pattern);
            put(lm, "template", a.label.template);
            putList(lm, "alsoExtract", a.label.alsoExtract);
            m.put("label", lm);
        }
        return m;
    }

    // ---------- helpers ----------

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : List.of();
    }

    private static List<String> strList(Object o) {
        if (!(o instanceof List)) return null;
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) o) out.add(String.valueOf(x));
        return out;
    }

    private static long asLong(Object o, long def) {
        if (o instanceof Number) return ((Number) o).longValue();
        try { return o == null ? def : Long.parseLong(String.valueOf(o)); } catch (Exception e) { return def; }
    }

    private static boolean asBool(Object o, boolean def) {
        return o instanceof Boolean ? (Boolean) o : def;
    }

    private static Direction dir(Object o, Direction def) {
        String s = str(o);
        if (s == null) return def;
        try { return Direction.valueOf(s); } catch (Exception e) { return def; }
    }

    private static void put(Map<String, Object> m, String k, String v) { if (v != null) m.put(k, v); }
    private static void putList(Map<String, Object> m, String k, List<String> v) {
        if (v != null && !v.isEmpty()) m.put(k, new ArrayList<Object>(v));
    }

    private RuleCodec() {}
}
