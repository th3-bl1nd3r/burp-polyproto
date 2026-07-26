package burp.polyproto.rule;

import burp.polyproto.core.Msg;
import burp.polyproto.core.Transport;

import java.util.List;
import java.util.regex.Pattern;

/**
 * A matcher. Top-level fields are AND-ed; {@link #anyOf} is an OR-group of nested matches; an empty
 * matcher matches everything (the catch-all "auto" rule). Host/content-type are case-insensitive
 * substring "any-of"; pathRegex is a Java regex find on the path without query.
 */
public final class Match {
    public Transport transport;
    public List<String> hostsAny;
    public String pathRegex;
    public List<String> methods;
    public List<String> contentTypesAny;
    public String wsSubprotocol;
    public List<String> headerNamePrefixAny;
    public List<HeaderMatch> headers;
    public List<Match> anyOf;

    private transient Pattern pathRe;

    public boolean matches(Msg m) {
        if (transport != null && m.transport() != transport) return false;

        if (hostsAny != null && !hostsAny.isEmpty()) {
            String h = m.host() == null ? "" : m.host().toLowerCase();
            if (!anyContains(h, hostsAny)) return false;
        }
        if (pathRegex != null && !pathRegex.isEmpty()) {
            String p = m.path() == null ? "" : m.path();
            try {
                if (pathRe == null) pathRe = Pattern.compile(pathRegex);
                if (!pathRe.matcher(p).find()) return false;
            } catch (Exception e) { return false; }
        }
        if (methods != null && !methods.isEmpty()) {
            String mm = m.method() == null ? "" : m.method();
            boolean ok = false;
            for (String s : methods) if (s.equalsIgnoreCase(mm)) { ok = true; break; }
            if (!ok) return false;
        }
        if (contentTypesAny != null && !contentTypesAny.isEmpty()) {
            String ct = m.contentType() == null ? "" : m.contentType().toLowerCase();
            if (!anyContains(ct, contentTypesAny)) return false;
        }
        if (wsSubprotocol != null && !wsSubprotocol.isEmpty()) {
            String w = m.wsSubprotocol() == null ? "" : m.wsSubprotocol();
            if (!wsSubprotocol.equalsIgnoreCase(w)) return false;
        }
        if (headerNamePrefixAny != null && !headerNamePrefixAny.isEmpty()) {
            boolean ok = false;
            for (String name : m.headerNames()) {
                String ln = name.toLowerCase();
                for (String pre : headerNamePrefixAny) {
                    if (ln.startsWith(pre.toLowerCase())) { ok = true; break; }
                }
                if (ok) break;
            }
            if (!ok) return false;
        }
        if (headers != null) {
            for (HeaderMatch hm : headers) if (!hm.matches(m)) return false;
        }
        if (anyOf != null && !anyOf.isEmpty()) {
            boolean ok = false;
            for (Match sub : anyOf) if (sub.matches(m)) { ok = true; break; }
            if (!ok) return false;
        }
        return true;
    }

    private static boolean anyContains(String hay, List<String> needles) {
        for (String s : needles) if (s != null && hay.contains(s.toLowerCase())) return true;
        return false;
    }
}
