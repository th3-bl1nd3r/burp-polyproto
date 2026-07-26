package burp.polyproto.stage.coding;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import burp.polyproto.util.Compression;

/** gzip (RFC 1952). Detected by magic 1F 8B; re-encodable. Delegates to the reused Compression. */
public final class GzipStage implements Stage {
    @Override public String id() { return "gzip"; }
    @Override public Kind kind() { return Kind.CODING; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return Compression.isGzip(in); }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        try {
            return Node.bytes(Compression.gunzip(in));
        } catch (Exception e) {
            throw new CodecException("gunzip failed", e);
        }
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        try {
            return Compression.gzip(edited.bytes);
        } catch (Exception e) {
            throw new CodecException("gzip failed", e);
        }
    }

    @Override public boolean canEncode() { return true; }
}
