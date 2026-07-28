package burp.polyproto.frontier;

import burp.polyproto.protobuf.ProtoText;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.coding.Lz4Codec;
import burp.polyproto.stage.format.ProtobufStage;
import burp.polyproto.util.Compression;
import burp.polyproto.util.JsonPretty;

import java.nio.charset.StandardCharsets;

/**
 * Round-trippable text form of a Frontier Frame for the editable WebSocket editor. Scalars and
 * headers are "key: value" lines; the payload is decoded to the best editable form under a marker:
 * protobuf (lossless {@link ProtoText}), JSON (pretty), plain text, or hex — unless a
 * {@code compress_type} header says it is zstd-dict compressed, in which case it is shown as hex
 * with a note (needs the runtime dictionary).
 *
 * <p>gzip and LZ4-block payloads are decompressed for display and re-compressed by {@link #parse},
 * so an edited frame goes back out in its transmitted form. Re-compression is not byte-identical to
 * the original — deflate output is implementation-specific — which is fine because Frontier frames
 * carry no per-frame signature.
 */
public final class FrameText {
    private static final String M_PROTO = "--- payload (protobuf, editable) ---";
    private static final String M_JSON  = "--- payload (json) ---";
    private static final String M_TEXT  = "--- payload (text) ---";
    private static final String M_HEX   = "--- payload (hex) ---";
    /** Marks a payload this class gunzipped for display, so {@link #parse} re-gzips it on the way out. */
    private static final String N_GZIP  = "payload_note: decompressed from gzip";

    private enum Kind { PROTO, JSON, TEXT, HEX }

    public static String toText(Frame f) {
        StringBuilder sb = new StringBuilder();
        sb.append("seqid: ").append(f.seqid).append('\n');
        sb.append("logid: ").append(f.logid).append('\n');
        sb.append("service: ").append(f.service).append('\n');
        sb.append("method: ").append(f.method).append('\n');
        for (String[] h : f.headers) {
            sb.append("header ").append(h[0]).append(": ").append(h[1] == null ? "" : h[1]).append('\n');
        }
        if (f.payloadEncoding != null) sb.append("payload_encoding: ").append(f.payloadEncoding).append('\n');
        if (f.payloadType != null) sb.append("payload_type: ").append(f.payloadType).append('\n');
        if (f.logidnew != null) sb.append("logidnew: ").append(f.logidnew).append('\n');
        if (f.serverTiming != null) sb.append("server_timing: ").append(f.serverTiming).append('\n');
        if (f.msgId != null) sb.append("msg_id: ").append(f.msgId).append('\n');

        byte[] raw = f.payload == null ? new byte[0] : f.payload;
        String compress = compressType(f);
        boolean lz4 = f.payloadEncoding != null && f.payloadEncoding.toLowerCase().contains("lz4");

        byte[] p = raw;
        boolean handled = false;
        if (compress != null) {
            String ver = header(f, "zstd_dict_version");
            sb.append("payload_note: compressed (").append(compress)
              .append(ver != null ? " v" + ver : "")
              .append(") — cannot decode without the runtime dictionary\n");
            sb.append(M_HEX).append('\n').append(hex(raw));
            handled = true;
        } else if (lz4) {
            try {
                p = Lz4Codec.decompress(raw);
                sb.append("payload_note: decompressed from ").append(f.payloadEncoding).append(" (LZ4 block)\n");
            } catch (Exception e) {
                sb.append("payload_note: ").append(f.payloadEncoding).append(" (LZ4 block) — could not decompress\n");
                sb.append(M_HEX).append('\n').append(hex(raw));
                handled = true;
            }
        } else if (Compression.isGzip(raw)) {
            // Frontier ships gzip payloads under payload_encoding: gzip. Trust the magic rather than
            // the header, but emit N_GZIP so parse() knows to re-compress an edited frame.
            try {
                p = Compression.gunzip(raw);
                sb.append(N_GZIP).append('\n');
            } catch (Exception e) {
                sb.append("payload_note: gzip — could not decompress\n");
                sb.append(M_HEX).append('\n').append(hex(raw));
                handled = true;
            }
        }

        if (!handled) {
            if (isJson(f, p)) {
                sb.append(M_JSON).append('\n').append(JsonPretty.pretty(new String(p, StandardCharsets.UTF_8)));
            } else if (ProtobufStage.isProtobuf(p)) {
                sb.append(M_PROTO).append('\n').append(ProtoText.encode(p));
            } else {
                String s = Protobuf.asPrintable(p);
                if (s != null) sb.append(M_TEXT).append('\n').append(s);
                else sb.append(M_HEX).append('\n').append(hex(p));
            }
        }
        return sb.toString();
    }

    public static Frame parse(String text) {
        Frame f = new Frame();
        String[] lines = text.split("\n", -1);
        Kind kind = null;
        int payloadStart = -1;
        String note = "";
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String t = line.trim();
            if (t.startsWith("--- payload (")) {
                if (t.contains("protobuf")) kind = Kind.PROTO;
                else if (t.contains("json")) kind = Kind.JSON;
                else if (t.contains("hex")) kind = Kind.HEX;
                else kind = Kind.TEXT;
                payloadStart = i + 1;
                break;
            }
            if (t.isEmpty()) continue;
            int c = line.indexOf(':');
            if (c < 0) continue;
            String key = line.substring(0, c).trim();
            String val = line.substring(c + 1).trim();
            if (key.startsWith("header ")) {
                f.headers.add(new String[]{ key.substring(7).trim(), val });
                continue;
            }
            switch (key) {
                case "seqid": f.seqid = parseLong(val); break;
                case "logid": f.logid = parseLong(val); break;
                case "service": f.service = (int) parseLong(val); break;
                case "method": f.method = (int) parseLong(val); break;
                case "payload_encoding": f.payloadEncoding = val; break;
                case "payload_type": f.payloadType = val; break;
                case "logidnew": f.logidnew = val; break;
                case "server_timing": f.serverTiming = val; break;
                case "msg_id": f.msgId = val; break;
                case "payload_note": note = val.toLowerCase(); break;
                default: break; // unknown lines are informational
            }
        }
        if (payloadStart >= 0 && payloadStart < lines.length) {
            StringBuilder body = new StringBuilder();
            for (int j = payloadStart; j < lines.length; j++) {
                if (j > payloadStart) body.append('\n');
                body.append(lines[j]);
            }
            String bodyStr = body.toString();
            switch (kind == null ? Kind.TEXT : kind) {
                case HEX:
                    f.payload = unhex(bodyStr);
                    break;
                case PROTO:
                    try { f.payload = ProtoText.parse(bodyStr); }
                    catch (Exception e) { f.payload = bodyStr.getBytes(StandardCharsets.UTF_8); }
                    break;
                case JSON:
                case TEXT:
                default:
                    f.payload = bodyStr.getBytes(StandardCharsets.UTF_8);
                    break;
            }
            // Reverse whatever toText() decompressed for display. Never for a hex payload: that is
            // shown as the exact wire bytes, so it is already in its transmitted form.
            if (kind != Kind.HEX) {
                String enc = f.payloadEncoding == null ? "" : f.payloadEncoding.toLowerCase();
                if (enc.contains("lz4")) {
                    try { f.payload = Lz4Codec.compress(f.payload); } catch (Exception ignore) { }
                } else if (enc.contains("gzip") || note.contains("gzip")) {
                    try { f.payload = Compression.gzip(f.payload); } catch (Exception ignore) { }
                }
            }
        } else {
            f.payload = new byte[0];
        }
        return f;
    }

    private static String compressType(Frame f) {
        String v = header(f, "compress_type");
        return (v != null && !v.isEmpty() && !"none".equalsIgnoreCase(v)) ? v : null;
    }

    private static boolean isJson(Frame f, byte[] p) {
        if ("json".equalsIgnoreCase(f.payloadEncoding)) return Protobuf.asPrintable(p) != null;
        if (Protobuf.asPrintable(p) == null) return false;
        int i = 0;
        while (i < p.length && (p[i] == ' ' || p[i] == '\n' || p[i] == '\r' || p[i] == '\t')) i++;
        return i < p.length && (p[i] == '{' || p[i] == '[');
    }

    private static String header(Frame f, String key) {
        for (String[] h : f.headers) if (h[0].equalsIgnoreCase(key)) return h[1];
        return null;
    }

    private static long parseLong(String s) {
        try { return Long.parseLong(s.trim()); }
        catch (Exception e) {
            try { return Long.parseUnsignedLong(s.trim()); } catch (Exception e2) { return 0L; }
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            sb.append(String.format("%02x", b[i] & 0xff));
            if ((i + 1) % 32 == 0) sb.append('\n');
        }
        return sb.toString();
    }

    private static byte[] unhex(String s) {
        StringBuilder clean = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) clean.append(c);
        }
        int n = clean.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private FrameText() {}
}
