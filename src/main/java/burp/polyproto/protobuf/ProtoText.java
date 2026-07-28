package burp.polyproto.protobuf;

import burp.polyproto.protobuf.Protobuf.Field;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lossless, editable text form of a protobuf message (protoscope-style), used so HTTP
 * request bodies can be modified in Burp and re-serialized. Round-trips any wire message:
 *   1: 42                      varint
 *   3: 99i32   / 3: 99i64      fixed32 / fixed64
 *   8: "text"                  length-delimited UTF-8 string
 *   8: {                       length-delimited nested message
 *     1: 5
 *   }
 *   8: `1f8b...`               length-delimited raw bytes (hex)
 * A trailing "  # name" comment (added by the schema overlay) is ignored on parse.
 */
public final class ProtoText {

    // ---------------- encode (bytes -> text) ----------------
    public static String encode(byte[] b) {
        StringBuilder sb = new StringBuilder();
        enc(b, 0, sb);
        return sb.toString();
    }

    private static void enc(byte[] b, int indent, StringBuilder sb) {
        List<Field> fs;
        try {
            fs = Protobuf.parse(b);
        } catch (Exception e) {
            pad(sb, indent);
            sb.append("# <").append(b.length).append(" non-protobuf bytes: ").append(hex(b)).append(">\n");
            return;
        }
        for (Field f : fs) {
            pad(sb, indent);
            sb.append(f.number).append(": ");
            switch (f.wireType) {
                case Protobuf.VARINT: sb.append(f.varint).append('\n'); break;
                case Protobuf.I64: sb.append(f.i64).append("i64\n"); break;
                case Protobuf.I32: sb.append(f.i32).append("i32\n"); break;
                case Protobuf.LEN: encLen(f, indent, sb); break;
                default: sb.append('\n');
            }
        }
    }

    private static void encLen(Field f, int indent, StringBuilder sb) {
        if (Protobuf.looksNested(f.data)) {
            sb.append("{\n");
            enc(f.data, indent + 1, sb);
            pad(sb, indent);
            sb.append("}\n");
            return;
        }
        String s = Protobuf.asCleanString(f.data);
        if (s != null) {
            sb.append('"').append(escape(s)).append("\"\n");
            return;
        }
        sb.append('`').append(hex(f.data)).append("`\n");
    }

    // ---------------- parse (text -> bytes) ----------------
    public static byte[] parse(String text) {
        String[] lines = text.split("\n", -1);
        int[] pos = { 0 };
        return parseFields(lines, pos, false);
    }

    private static byte[] parseFields(String[] lines, int[] pos, boolean nested) {
        List<Field> fields = new ArrayList<>();
        while (pos[0] < lines.length) {
            String line = lines[pos[0]].trim();
            pos[0]++;
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.equals("}")) {
                if (nested) break;
                continue;
            }
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            String tagStr = line.substring(0, colon).trim();
            int sp = tagStr.indexOf(' ');
            if (sp >= 0) tagStr = tagStr.substring(0, sp); // ignore "8 body" name annotation
            int tag;
            try { tag = Integer.parseInt(tagStr); } catch (Exception e) { continue; }
            String val = line.substring(colon + 1).trim();
            if (val.isEmpty()) continue;

            if (val.startsWith("{")) {
                byte[] sub = parseFields(lines, pos, true);
                fields.add(Protobuf.len(tag, sub));
            } else if (val.charAt(0) == '"') {
                fields.add(Protobuf.len(tag, unquote(val).getBytes(StandardCharsets.UTF_8)));
            } else if (val.charAt(0) == '`') {
                int end = val.indexOf('`', 1);
                String h = end > 0 ? val.substring(1, end) : val.substring(1);
                fields.add(Protobuf.len(tag, unhex(h)));
            } else {
                String num = stripComment(val);
                if (num.endsWith("i32")) {
                    Field f = new Field();
                    f.number = tag; f.wireType = Protobuf.I32; f.i32 = (int) parseLong(num.substring(0, num.length() - 3));
                    fields.add(f);
                } else if (num.endsWith("i64")) {
                    Field f = new Field();
                    f.number = tag; f.wireType = Protobuf.I64; f.i64 = parseLong(num.substring(0, num.length() - 3));
                    fields.add(f);
                } else {
                    fields.add(Protobuf.varint(tag, parseLong(num)));
                }
            }
        }
        return Protobuf.encode(fields);
    }

    // ---------------- helpers ----------------
    private static String stripComment(String v) {
        int h = v.indexOf('#');
        return (h >= 0 ? v.substring(0, h) : v).trim();
    }

    private static long parseLong(String s) {
        s = s.trim();
        try { return Long.parseLong(s); }
        catch (Exception e) {
            try { return Long.parseUnsignedLong(s); } catch (Exception e2) { return 0L; }
        }
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    // Never let a raw control byte sit invisibly in the editable text: an editor or
                    // clipboard round-trip that drops it would silently corrupt the re-encode.
                    if (c < 0x20 || c == 0x7f) sb.append(String.format("\\x%02x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String unquote(String val) {
        int last = val.lastIndexOf('"');
        String body = (last > 0) ? val.substring(1, last) : val.substring(1);
        StringBuilder sb = new StringBuilder(body.length());
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\\' && i + 1 < body.length()) {
                char n = body.charAt(++i);
                switch (n) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case 'x':
                        if (i + 2 < body.length()) {
                            try {
                                sb.append((char) Integer.parseInt(body.substring(i + 1, i + 3), 16));
                                i += 2;
                            } catch (NumberFormatException e) { sb.append('x'); }
                        } else {
                            sb.append('x');
                        }
                        break;
                    default: sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte value : b) sb.append(String.format("%02x", value & 0xff));
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
        for (int i = 0; i < n; i++) out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private static void pad(StringBuilder sb, int indent) {
        for (int i = 0; i < indent; i++) sb.append("  ");
    }

    private ProtoText() {}
}
