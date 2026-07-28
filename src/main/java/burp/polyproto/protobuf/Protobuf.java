package burp.polyproto.protobuf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Schema-less protobuf wire-format reader/writer + pretty renderer.
 * No .proto needed: fields are decoded structurally (varint / i64 / len / i32).
 * Length-delimited fields are heuristically rendered as string, nested message, or hex.
 */
public final class Protobuf {
    public static final int VARINT = 0, I64 = 1, LEN = 2, I32 = 5;

    public static final class Field {
        public int number, wireType;
        public long varint;  // VARINT
        public long i64;     // I64
        public int i32;      // I32
        public byte[] data;  // LEN
    }

    // ---------------- reader ----------------
    public static List<Field> parse(byte[] b) {
        return parse(b, 0, b.length);
    }

    public static List<Field> parse(byte[] b, int off, int end) {
        List<Field> out = new ArrayList<>();
        int[] p = { off };
        while (p[0] < end) {
            long tag = readVarint(b, p, end);
            int num = (int) (tag >>> 3);
            int wt = (int) (tag & 7);
            if (num == 0) throw new IllegalArgumentException("field 0");
            Field f = new Field();
            f.number = num;
            f.wireType = wt;
            switch (wt) {
                case VARINT: f.varint = readVarint(b, p, end); break;
                case I64:    f.i64 = readLE(b, p, 8, end); break;
                case I32:    f.i32 = (int) readLE(b, p, 4, end); break;
                case LEN: {
                    int len = (int) readVarint(b, p, end);
                    if (len < 0 || p[0] + len > end) throw new IllegalArgumentException("bad len");
                    f.data = Arrays.copyOfRange(b, p[0], p[0] + len);
                    p[0] += len;
                    break;
                }
                default: throw new IllegalArgumentException("bad wiretype " + wt);
            }
            out.add(f);
        }
        return out;
    }

    private static long readVarint(byte[] b, int[] p, int end) {
        long r = 0;
        int shift = 0;
        while (true) {
            if (p[0] >= end) throw new IllegalArgumentException("varint eof");
            int c = b[p[0]++] & 0xff;
            r |= ((long) (c & 0x7f)) << shift;
            if ((c & 0x80) == 0) break;
            shift += 7;
            if (shift > 63) throw new IllegalArgumentException("varint too long");
        }
        return r;
    }

    private static long readLE(byte[] b, int[] p, int n, int end) {
        if (p[0] + n > end) throw new IllegalArgumentException("fixed eof");
        long r = 0;
        for (int i = 0; i < n; i++) r |= ((long) (b[p[0]++] & 0xff)) << (8 * i);
        return r;
    }

    // ---------------- writer ----------------
    public static byte[] encode(List<Field> fields) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (Field f : fields) {
            writeVarint(o, ((long) f.number << 3) | f.wireType);
            switch (f.wireType) {
                case VARINT: writeVarint(o, f.varint); break;
                case I64:    writeLE(o, f.i64, 8); break;
                case I32:    writeLE(o, f.i32 & 0xffffffffL, 4); break;
                case LEN:    writeVarint(o, f.data.length); o.write(f.data, 0, f.data.length); break;
            }
        }
        return o.toByteArray();
    }

    static void writeVarint(ByteArrayOutputStream o, long v) {
        while (true) {
            int c = (int) (v & 0x7f);
            v >>>= 7;
            if (v != 0) { o.write(c | 0x80); } else { o.write(c); break; }
        }
    }

    static void writeLE(ByteArrayOutputStream o, long v, int n) {
        for (int i = 0; i < n; i++) { o.write((int) (v & 0xff)); v >>>= 8; }
    }

    public static Field varint(int num, long v) {
        Field f = new Field(); f.number = num; f.wireType = VARINT; f.varint = v; return f;
    }
    public static Field len(int num, byte[] d) {
        Field f = new Field(); f.number = num; f.wireType = LEN; f.data = d; return f;
    }
    public static Field str(int num, String s) {
        return len(num, s.getBytes(StandardCharsets.UTF_8));
    }

    // ---------------- pretty render ----------------
    public static String render(byte[] b, Map<Integer, String> names) {
        StringBuilder sb = new StringBuilder();
        render(b, names, 0, sb);
        return sb.toString();
    }

    private static void render(byte[] b, Map<Integer, String> names, int indent, StringBuilder sb) {
        List<Field> fs;
        try {
            fs = parse(b);
        } catch (Exception e) {
            pad(sb, indent);
            sb.append("<").append(b.length).append(" raw bytes> ").append(hexPreview(b)).append("\n");
            return;
        }
        for (Field f : fs) {
            pad(sb, indent);
            sb.append(f.number);
            String nm = names != null ? names.get(f.number) : null;
            if (nm != null) sb.append(" ").append(nm);
            switch (f.wireType) {
                case VARINT: sb.append(" (varint): ").append(f.varint).append("\n"); break;
                case I64:    sb.append(" (i64): ").append(f.i64).append("\n"); break;
                case I32:    sb.append(" (i32): ").append(f.i32).append("\n"); break;
                case LEN:    renderLen(f.data, indent, sb); break;
            }
        }
    }

    private static void renderLen(byte[] d, int indent, StringBuilder sb) {
        if (looksNested(d)) { sb.append(" (msg):\n"); render(d, null, indent + 1, sb); return; }
        String s = asCleanString(d);
        if (s != null) { sb.append(" (str): \"").append(s).append("\"\n"); return; }
        sb.append(" (bytes[").append(d.length).append("]): ").append(hexPreview(d)).append("\n");
    }

    // ---------------- LEN payload classification ----------------

    /** Largest field number we will believe when guessing that a LEN payload is a nested message. */
    private static final int MAX_NESTED_FIELD = 512;

    /**
     * Should this length-delimited payload be expanded as a nested message rather than shown as a
     * string? Must be tried BEFORE {@link #asCleanString}: a nested message carrying tokens, IDs or
     * URLs is well over 90% printable, so a printable-first test flattens it into one mangled value
     * and its tag/length bytes surface as stray characters.
     *
     * <p>Guarded against the opposite mistake — short text that parses by luck, e.g. {@code "PB"}
     * reading as {@code 10: 66}. The fields must re-encode to byte-identical input, carry plausible
     * numbers, and — when the payload is clean text end to end — include at least one
     * length-delimited field, which coincidental text effectively never does.
     */
    public static boolean looksNested(byte[] d) {
        if (d == null || d.length < 2) return false;
        List<Field> fs;
        try { fs = parse(d); } catch (Exception e) { return false; }
        if (fs.isEmpty()) return false;
        for (Field f : fs) if (f.number > MAX_NESTED_FIELD) return false;
        if (!Arrays.equals(encode(fs), d)) return false; // non-canonical: never was a message
        if (asCleanString(d) == null) return true;
        for (Field f : fs) if (f.wireType == LEN) return true;
        return false;
    }

    /**
     * The UTF-8 text of a length-delimited payload, or null when the bytes are not plainly text.
     * Stricter than {@link #asPrintable}: a single C0 control byte (other than tab/CR/LF) means the
     * buffer carries framing rather than text — the signature of a nested message.
     */
    public static String asCleanString(byte[] d) {
        if (d == null) return null;
        if (d.length == 0) return "";
        for (byte value : d) {
            int c = value & 0xff;
            if (c == 0x09 || c == 0x0a || c == 0x0d) continue;
            if (c < 0x20 || c == 0x7f) return null;
        }
        String s = new String(d, StandardCharsets.UTF_8);
        return s.contains("�") ? null : s; // invalid UTF-8
    }

    /**
     * Return the UTF-8 string only if the bytes look like printable text. Tolerant (90% threshold),
     * so it stays the right gate for classifying a whole body; for a LEN payload inside a message
     * use {@link #asCleanString} together with {@link #looksNested}.
     */
    public static String asPrintable(byte[] d) {
        if (d.length == 0) return "";
        int printable = 0;
        for (byte value : d) {
            int c = value & 0xff;
            if (c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c < 0x7f) || c >= 0x80) printable++;
        }
        if ((double) printable / d.length < 0.90) return null;
        String s = new String(d, StandardCharsets.UTF_8);
        if (s.contains("�")) return null; // invalid UTF-8
        return s;
    }

    private static void pad(StringBuilder sb, int indent) {
        for (int i = 0; i < indent; i++) sb.append("  ");
    }

    private static String hexPreview(byte[] b) {
        StringBuilder sb = new StringBuilder();
        int n = Math.min(b.length, 32);
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i] & 0xff));
        if (b.length > n) sb.append("...");
        return sb.toString();
    }

    private Protobuf() {}
}
