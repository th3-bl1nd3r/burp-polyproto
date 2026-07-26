package burp.polyproto.stage.framing;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import burp.polyproto.util.Chunked;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * HTTP/1.1 chunked transfer-encoding de-framer (some OEC/TokoPro responses arrive over HTTP/2
 * with the origin's chunked framing still embedded). Delegates to the reused, whole-buffer
 * validated {@link Chunked}. On re-encode it emits a single chunk plus the terminator.
 */
public final class ChunkedStage implements Stage {
    @Override public String id() { return "dechunk"; }
    @Override public Kind kind() { return Kind.FRAMING; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return Chunked.dechunk(in) != null; }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        byte[] out = Chunked.dechunk(in);
        if (out == null) throw new CodecException("not chunked");
        return Node.bytes(out);
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        byte[] body = edited.bytes;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] size = Integer.toHexString(body.length).getBytes(StandardCharsets.US_ASCII);
        out.write(size, 0, size.length);
        out.write('\r'); out.write('\n');
        out.write(body, 0, body.length);
        out.write('\r'); out.write('\n');
        out.write('0'); out.write('\r'); out.write('\n'); out.write('\r'); out.write('\n');
        return out.toByteArray();
    }

    @Override public boolean canEncode() { return true; }
}
