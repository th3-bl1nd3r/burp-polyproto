package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import burp.polyproto.util.Json;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * application/x-www-form-urlencoded whose VALUES are themselves (url-encoded) JSON — the generalized
 * Meta/Facebook shape, e.g. {@code variables=%7B...%7D&fb_api_req_friendly_name=Foo}. Each value that
 * decodes to a JSON object/array is parsed and rendered inline so the whole body reads as one JSON
 * map; on edit the map is re-emitted, JSON values re-compacted, and the pairs re-form-encoded.
 *
 * <p>Outranks the plain {@code form} stage only when at least one value really is JSON (see sniff).
 */
public final class FormJsonStage implements Stage {
    @Override public String id() { return "form+json"; }
    @Override public Kind kind() { return Kind.FORMAT; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        if (Protobuf.asPrintable(in) == null || !FormStage.looksForm(in)) return false;
        String body = new String(in, StandardCharsets.UTF_8);
        for (String tok : body.split("&")) {
            int eq = tok.indexOf('=');
            if (eq < 0) continue;
            String v = dec(tok.substring(eq + 1));
            if (asJson(v) != null) return true;
        }
        return false;
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        if (in == null || in.length == 0) throw new CodecException("empty body");
        String body = new String(in, StandardCharsets.UTF_8);
        Map<String, Object> map = new LinkedHashMap<>();
        for (String tok : body.split("&")) {
            if (tok.isEmpty()) continue;
            int eq = tok.indexOf('=');
            String k, v;
            if (eq < 0) { k = dec(tok); v = ""; }
            else { k = dec(tok.substring(0, eq)); v = dec(tok.substring(eq + 1)); }
            Object parsed = asJson(v);
            map.put(k, parsed != null ? parsed : v);
        }
        return Node.text(Json.pretty(map), "form+json");
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        try {
            Map<String, Object> map = Json.parseObject(edited.text);
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Object> e : map.entrySet()) {
                Object val = e.getValue();
                String valStr = (val instanceof Map || val instanceof List)
                        ? Json.emit(val)
                        : String.valueOf(val);
                if (sb.length() > 0) sb.append('&');
                sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                  .append('=')
                  .append(URLEncoder.encode(valStr, StandardCharsets.UTF_8));
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CodecException("form+json re-encode failed", e);
        }
    }

    @Override public boolean canEncode() { return true; }

    /** URL-decode leniently: on malformed %-escapes, fall back to the raw substring. */
    private static String dec(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return s;
        }
    }

    /** If {@code v} (ignoring surrounding whitespace) starts with '{' or '[' and parses, the parsed
     *  object/array; otherwise null. */
    private static Object asJson(String v) {
        String t = v.trim();
        if (t.isEmpty()) return null;
        char c = t.charAt(0);
        if (c != '{' && c != '[') return null;
        try {
            return Json.parse(t);
        } catch (RuntimeException ex) {
            return null;
        }
    }
}
