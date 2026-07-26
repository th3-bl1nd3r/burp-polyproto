package burp.polyproto.stage.coding;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.brotli.dec.BrotliInputStream;

/**
 * Brotli content-coding (RFC 7932). Decode-only: the bundled org.brotli.dec provides no pure-Java
 * encoder. Brotli has no magic number, so {@link #sniff} always returns {@code false}; this stage is
 * only ever reached via an explicit rule/token or a {@code Content-Encoding: br} header. Because the
 * layer cannot be re-compressed, {@link #canEncode} is {@code false} and the engine drops the coding
 * header on edit.
 */
public final class BrotliStage implements Stage {
    @Override public String id() { return "br"; }
    @Override public Kind kind() { return Kind.CODING; }

    /** No reliable magic — never blind-detected. Only an explicit rule/header selects brotli. */
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return false; }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        try (BrotliInputStream b = new BrotliInputStream(new ByteArrayInputStream(in));
             ByteArrayOutputStream o = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = b.read(buf)) > 0) {
                o.write(buf, 0, r);
            }
            return Node.bytes(o.toByteArray());
        } catch (Exception e) {
            throw new CodecException("brotli decode failed", e);
        }
    }

    /** Identity: no pure-Java brotli encoder, so the edited bytes pass through unchanged. */
    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        return edited.bytes;
    }

    @Override public boolean canEncode() { return false; }
}
