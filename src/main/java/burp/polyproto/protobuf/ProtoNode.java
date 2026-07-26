package burp.polyproto.protobuf;

import java.util.ArrayList;
import java.util.List;

/**
 * A structured, foldable view of a decoded protobuf message — the model behind the tree UI,
 * the bytes "decode-in-place" action, and copy-value/hex/path. Built by {@code ProtoNodes.parse}
 * from raw bytes + an optional {@link ProtoSchema} overlay; rendered by the tree view.
 *
 * <p>A MESSAGE/ROOT node has {@link #children}; a scalar node has a {@link #value} display string.
 * Every node keeps its {@link #raw} value bytes so a LEN field can be re-decoded (as protobuf/gzip/
 * base64/...) on demand and so "copy as hex" works on any field.
 */
public final class ProtoNode {

    public enum Kind { ROOT, MESSAGE, VARINT, I64, I32, STRING, BYTES }

    public Kind kind;
    public int field;          // protobuf field number (0 for ROOT)
    public int wireType;       // 0 VARINT, 1 I64, 2 LEN, 5 I32 (-1 for ROOT)
    public String name;        // schema field name, or null (render numbered)
    public String typeLabel;   // short tag shown dim: "msg","varint","i64","i32","str","bytes"
    public String value;       // display string for scalars; null for ROOT/MESSAGE
    public byte[] raw;         // the field's value bytes (LEN payload / varint-as-bytes); never null
    public final List<ProtoNode> children = new ArrayList<>();

    public ProtoNode(Kind kind) {
        this.kind = kind;
        this.raw = EMPTY;
    }

    public boolean isMessage() { return kind == Kind.MESSAGE || kind == Kind.ROOT; }
    public boolean isBytes()   { return kind == Kind.BYTES; }
    public boolean hasChildren() { return !children.isEmpty(); }

    public ProtoNode add(ProtoNode child) { children.add(child); return this; }

    /** "6" or "6 body" — the label shown before the value/brace. */
    public String label() {
        if (kind == Kind.ROOT) return "";
        return name != null ? field + " " + name : String.valueOf(field);
    }

    /** Dotted field path from the root, e.g. "6.500.2" — for copy-path. */
    public String path(ProtoNode parent, String parentPath) {
        return parentPath == null || parentPath.isEmpty()
                ? String.valueOf(field) : parentPath + "." + field;
    }

    private static final byte[] EMPTY = new byte[0];

    public static ProtoNode root() { return new ProtoNode(Kind.ROOT); }
}
