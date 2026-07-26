package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

/**
 * Terminal "pick the best format" stage for the {@code auto-format} token: sniff the buffer, run
 * the chosen format stage, and remember which one so encode() can reverse it. Lets a rule pin the
 * transport ({@code ["dechunk?","gzip?","auto-format"]}) while leaving the body format to detection.
 */
public final class AutoFormatStage implements Stage {
    @Override public String id() { return "auto-format"; }
    @Override public Kind kind() { return Kind.FORMAT; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return true; }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        Stage chosen = byId(FormatSniffer.classify(in, ctx));
        Node n = chosen.decode(in, ctx);
        n.meta.put("auto.format", chosen.id());
        return n;
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        String fmt = (String) edited.meta.get("auto.format");
        return byId(fmt).encode(edited, ctx);
    }

    @Override public boolean canEncode() { return true; }

    static Stage byId(String id) {
        if ("xml".equals(id)) return new XmlStage();
        if ("json".equals(id)) return new JsonStage();
        if ("form+json".equals(id)) return new FormJsonStage();
        if ("form".equals(id)) return new FormStage();
        if ("protobuf".equals(id)) return new ProtobufStage();
        if ("text".equals(id)) return new TextStage();
        return new RawStage();
    }
}
