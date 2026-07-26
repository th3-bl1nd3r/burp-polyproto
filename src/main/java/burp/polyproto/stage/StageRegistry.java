package burp.polyproto.stage;

import burp.polyproto.core.PipelineCtx;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Token → {@link Stage} factory registry and the single extensibility seam. A token may carry a
 * ":arg" (e.g. {@code envelope:tiktok.frontier}) and/or a trailing "?" (optional); both are
 * stripped to find the base token. Higher priority = probed earlier in {@link #firstMatching}.
 */
public final class StageRegistry {
    private final Map<String, Supplier<Stage>> factories = new LinkedHashMap<>();
    private final Map<String, Integer> priorities = new HashMap<>();

    public void register(String token, int priority, Supplier<Stage> factory) {
        factories.put(token, factory);
        priorities.put(token, priority);
    }

    public void register(String token, Supplier<Stage> factory) { register(token, 0, factory); }

    /** Strip a trailing "?" and any ":arg", leaving the registered base token. */
    public static String base(String token) {
        String t = token;
        if (t.endsWith("?")) t = t.substring(0, t.length() - 1);
        int c = t.indexOf(':');
        return c >= 0 ? t.substring(0, c) : t;
    }

    /** The ":arg" portion of a token, or null. */
    public static String arg(String token) {
        String t = token;
        if (t.endsWith("?")) t = t.substring(0, t.length() - 1);
        int c = t.indexOf(':');
        return c >= 0 ? t.substring(c + 1) : null;
    }

    public Stage resolve(String token, PipelineCtx ctx) {
        String b = base(token);
        String a = arg(token);
        Supplier<Stage> f = factories.get(b);
        if (f == null) return null;
        Stage s = f.get();
        if (a != null && ctx != null) ctx.attrs.put(b + ".arg", a);
        return s;
    }

    public boolean isKnown(String token) { return factories.containsKey(base(token)); }

    public Set<String> tokens() { return new LinkedHashSet<>(factories.keySet()); }

    public int priority(String token) { return priorities.getOrDefault(base(token), 0); }

    /** First registered stage of one of {@code kinds} whose sniff() fires on {@code buf}, priority-desc. */
    public Stage firstMatching(EnumSet<Stage.Kind> kinds, byte[] buf, PipelineCtx ctx) {
        List<String> ks = new ArrayList<>(factories.keySet());
        ks.sort((x, y) -> Integer.compare(priorities.getOrDefault(y, 0), priorities.getOrDefault(x, 0)));
        for (String k : ks) {
            Stage s = factories.get(k).get();
            if (!kinds.contains(s.kind())) continue;
            try {
                if (s.sniff(buf, ctx)) return s;
            } catch (Exception ignore) { /* a stage that throws in sniff just doesn't match */ }
        }
        return null;
    }
}
