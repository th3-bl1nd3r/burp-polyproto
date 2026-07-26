package burp.polyproto.stage.format;

import burp.polyproto.core.Direction;
import burp.polyproto.core.PipelineCtx;
import burp.polyproto.pack.SchemaPacks;
import burp.polyproto.protobuf.ProtoSchema;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.protobuf.ProtoText;
import burp.polyproto.protobuf.SchemaRenderer;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.util.List;

/**
 * Terminal protobuf format. The editable text is the lossless protoscope form ({@link ProtoText}),
 * so edits round-trip byte-exact and unknown fields survive. Field-name overlays (schema packs)
 * are layered on later; without one, fields render numbered.
 */
public final class ProtobufStage implements Stage {
    @Override public String id() { return "protobuf"; }
    @Override public Kind kind() { return Kind.FORMAT; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return isProtobuf(in); }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        try {
            // With a schema pack, render RESPONSES as a named tree (read-only, like the old tool);
            // requests and un-schema'd bodies stay numbered ProtoText so they remain editable.
            ProtoSchema schema = ctx != null && ctx.schemaPack != null
                    ? SchemaPacks.get().proto(ctx.schemaPack, ctx.direction) : null;
            Node n;
            if (schema != null && ctx.direction == Direction.RESPONSE) {
                n = Node.text(SchemaRenderer.render(in, schema), "protobuf");
                n.meta.put("readonly", true);
                n.meta.put("raw.bytes", in);
            } else {
                n = Node.text(ProtoText.encode(in), "protobuf");
            }
            // stash the message bytes + name overlay so the panel can build the foldable tree
            n.meta.put("proto.bytes", in);
            if (schema != null) n.meta.put("proto.schema", schema);
            return n;
        } catch (Exception e) {
            throw new CodecException("protobuf decode failed", e);
        }
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        try {
            Object raw = edited.meta.get("raw.bytes");
            if (raw instanceof byte[]) return (byte[]) raw; // named tree is read-only passthrough
            return ProtoText.parse(edited.text);
        } catch (Exception e) {
            throw new CodecException("protobuf re-encode failed", e);
        }
    }

    @Override public boolean canEncode() { return true; }

    /**
     * Strict protobuf detector: parses cleanly to ≥1 field with sane field numbers and valid wire
     * types (the parser consumes the whole buffer or throws). Works on printable buffers too, so a
     * string-heavy protobuf (emails/names) is not mistaken for plain text — callers must check the
     * more specific printable formats (JSON/XML/form) BEFORE calling this.
     */
    public static boolean isProtobuf(byte[] b) {
        if (b == null || b.length < 2) return false;
        try {
            List<Protobuf.Field> fs = Protobuf.parse(b);
            if (fs.isEmpty()) return false;
            for (Protobuf.Field f : fs) {
                if (f.number < 1 || f.number > 536870911) return false;
                if (f.wireType != Protobuf.VARINT && f.wireType != Protobuf.I64
                        && f.wireType != Protobuf.LEN && f.wireType != Protobuf.I32) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
