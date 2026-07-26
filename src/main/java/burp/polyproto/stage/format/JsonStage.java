package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import burp.polyproto.util.JsonPretty;

import java.nio.charset.StandardCharsets;

/** Terminal JSON format: pretty-print for reading; edited text is re-emitted as UTF-8. */
public final class JsonStage implements Stage {
    @Override public String id() { return "json"; }
    @Override public Kind kind() { return Kind.FORMAT; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        return Protobuf.asPrintable(in) != null && looksJson(in);
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) {
        String s = new String(in, StandardCharsets.UTF_8);
        return Node.text(JsonPretty.pretty(s), "json");
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        return edited.text.getBytes(StandardCharsets.UTF_8);
    }

    @Override public boolean canEncode() { return true; }

    /** First non-whitespace byte is '{' or '['. */
    public static boolean looksJson(byte[] b) {
        if (b == null) return false;
        int i = 0;
        while (i < b.length && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t')) i++;
        return i < b.length && (b[i] == '{' || b[i] == '[');
    }
}
