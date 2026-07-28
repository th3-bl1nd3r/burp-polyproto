package burp.polyproto.protobuf;

import java.time.Instant;
import java.util.List;

/**
 * Builds the foldable {@link ProtoNode} tree from raw protobuf bytes plus an optional
 * {@link ProtoSchema} name overlay. This is the parser behind the tree view and the
 * "decode-in-place" action: schema-less structural decode (varint / i64 / len / i32),
 * with LEN fields heuristically classified as string, nested message, or opaque bytes.
 *
 * <p>Nested messages recurse using the matching {@link ProtoSchema#nested(int)} overlay,
 * so a named child message keeps its field names too. Every node retains its {@link ProtoNode#raw}
 * value bytes so a LEN payload can be re-decoded on demand and "copy as hex" works everywhere.
 */
public final class ProtoNodes {

    private static final byte[] EMPTY = new byte[0];

    // Plausible unix-milliseconds window: ~2001-09 .. ~2033-05. A varint in this range is
    // very likely a timestamp, so we surface a dim hint while keeping the raw number as value.
    private static final long TS_MIN = 1_000_000_000_000L;
    private static final long TS_MAX = 2_000_000_000_000L;

    /** Parse {@code data} into a {@link ProtoNode.Kind#ROOT} node. Never returns null. */
    public static ProtoNode parse(byte[] data, ProtoSchema schema) {
        ProtoNode root = ProtoNode.root();
        if (data == null || data.length == 0) return root;

        List<Protobuf.Field> fields;
        try {
            fields = Protobuf.parse(data);
        } catch (Exception e) {
            return root; // not decodable as protobuf — hand back an empty root
        }

        for (Protobuf.Field f : fields) {
            ProtoNode child = build(f, schema);
            root.add(child);
        }
        return root;
    }

    private static ProtoNode build(Protobuf.Field f, ProtoSchema schema) {
        ProtoNode child = new ProtoNode(ProtoNode.Kind.VARINT); // overwritten below per wire type
        child.field = f.number;
        child.wireType = f.wireType;
        child.name = schema != null ? schema.name(f.number) : null;
        child.raw = EMPTY;

        switch (f.wireType) {
            case Protobuf.VARINT:
                child.kind = ProtoNode.Kind.VARINT;
                child.typeLabel = varintLabel(f.varint);
                child.value = Long.toString(f.varint);
                break;
            case Protobuf.I64:
                child.kind = ProtoNode.Kind.I64;
                child.typeLabel = "i64";
                child.value = Long.toString(f.i64);
                break;
            case Protobuf.I32:
                child.kind = ProtoNode.Kind.I32;
                child.typeLabel = "i32";
                child.value = Integer.toString(f.i32);
                break;
            case Protobuf.LEN:
                classifyLen(child, f, schema);
                break;
            default:
                // Unreachable via Protobuf.parse (it rejects other wire types), but stay defensive.
                child.kind = ProtoNode.Kind.BYTES;
                child.typeLabel = "bytes";
                child.value = "0 bytes";
                break;
        }
        return child;
    }

    /** Decide whether a LEN payload is text, a nested message, or opaque bytes. */
    private static void classifyLen(ProtoNode child, Protobuf.Field f, ProtoSchema schema) {
        byte[] d = f.data != null ? f.data : EMPTY;
        child.raw = d;

        // If the schema declares this LEN field as a nested message, trust it — even when the
        // payload is string-heavy (e.g. a conversation full of IDs) and would look printable.
        ProtoSchema sub = schema != null ? schema.nested(f.number) : null;
        if (sub != null && d.length > 0) {
            child.kind = ProtoNode.Kind.MESSAGE;
            child.typeLabel = "msg";
            child.value = null;
            child.children.addAll(parse(d, sub).children);
            return;
        }

        // Nested-message detection comes BEFORE the text test: a message full of tokens/IDs reads as
        // printable, and treating it as a string flattens its fields into one mangled value.
        if (Protobuf.looksNested(d)) {
            child.kind = ProtoNode.Kind.MESSAGE;
            child.typeLabel = "msg";
            child.value = null; // message nodes render via children, not a scalar value
            child.children.addAll(parse(d, null).children);
            return;
        }

        String text = Protobuf.asCleanString(d);
        if (text != null) {
            child.kind = ProtoNode.Kind.STRING;
            child.typeLabel = "str";
            child.value = text;
            return;
        }

        child.kind = ProtoNode.Kind.BYTES;
        child.typeLabel = "bytes";
        child.value = d.length + " bytes";
    }

    /** "varint", or "varint 2023-11-14T22:13:20Z" when the value reads like a unix-ms timestamp. */
    private static String varintLabel(long v) {
        if (v >= TS_MIN && v <= TS_MAX) {
            try {
                return "varint " + Instant.ofEpochMilli(v);
            } catch (Exception ignore) {
                // fall through to the plain label
            }
        }
        return "varint";
    }

    private ProtoNodes() {}
}
