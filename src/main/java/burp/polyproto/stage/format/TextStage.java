package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.nio.charset.StandardCharsets;

/** Terminal plain-text: any sufficiently-printable UTF-8 buffer. */
public final class TextStage implements Stage {
    @Override public String id() { return "text"; }
    @Override public Kind kind() { return Kind.FORMAT; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return Protobuf.asPrintable(in) != null; }

    @Override public Node decode(byte[] in, PipelineCtx ctx) {
        String s = Protobuf.asPrintable(in);
        if (s == null) s = new String(in, StandardCharsets.UTF_8);
        return Node.text(s, "text");
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        return edited.text.getBytes(StandardCharsets.UTF_8);
    }

    @Override public boolean canEncode() { return true; }
}
