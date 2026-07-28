package burp.polyproto.protobuf;

import burp.polyproto.protobuf.Protobuf.Field;

import java.util.List;

/** Renders protobuf bytes as an indented tree, overlaying names from a ProtoSchema when available. */
public final class SchemaRenderer {

    public static String render(byte[] b, ProtoSchema schema) {
        StringBuilder sb = new StringBuilder();
        render(b, schema, 0, sb);
        return sb.toString();
    }

    private static void render(byte[] b, ProtoSchema schema, int indent, StringBuilder sb) {
        List<Field> fs;
        try {
            fs = Protobuf.parse(b);
        } catch (Exception e) {
            pad(sb, indent);
            sb.append("<").append(b.length).append(" non-protobuf bytes>\n");
            return;
        }
        for (Field f : fs) {
            pad(sb, indent);
            sb.append(f.number);
            String nm = schema != null ? schema.name(f.number) : null;
            if (nm != null) sb.append(' ').append(nm);
            switch (f.wireType) {
                case Protobuf.VARINT: sb.append(" = ").append(f.varint).append('\n'); break;
                case Protobuf.I64:    sb.append(" = ").append(f.i64).append(" (i64)\n"); break;
                case Protobuf.I32:    sb.append(" = ").append(f.i32).append(" (i32)\n"); break;
                case Protobuf.LEN:    renderLen(f, schema, indent, sb); break;
                default: sb.append('\n');
            }
        }
    }

    private static void renderLen(Field f, ProtoSchema schema, int indent, StringBuilder sb) {
        ProtoSchema sub = schema != null ? schema.nested(f.number) : null;
        if (sub != null) {
            sb.append(" {   // ").append(sub.name).append('\n');
            render(f.data, sub, indent + 1, sb);
            pad(sb, indent);
            sb.append("}\n");
            return;
        }
        if (Protobuf.looksNested(f.data)) {
            sb.append(" {\n");
            render(f.data, null, indent + 1, sb);
            pad(sb, indent);
            sb.append("}\n");
            return;
        }
        String s = Protobuf.asCleanString(f.data);
        if (s != null) {
            sb.append(" = \"").append(s).append("\"\n");
            return;
        }
        sb.append(" = <").append(f.data.length).append(" bytes>\n");
    }

    private static void pad(StringBuilder sb, int indent) {
        for (int i = 0; i < indent; i++) sb.append("  ");
    }

    private SchemaRenderer() {}
}
