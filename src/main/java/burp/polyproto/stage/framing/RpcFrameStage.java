package burp.polyproto.stage.framing;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * gRPC length-prefixed framing (Content-Type application/grpc). Each message is a 5-byte prefix —
 * 1 compressed-flag byte + a 4-byte big-endian length — followed by the (possibly compressed)
 * message. This stage handles the common UNARY case of exactly one message: it strips the prefix
 * and yields the payload bytes (still compressed if the flag is set, so the coding stage that
 * follows peels gzip/zstd/deflate). The compression flag is remembered so {@link #encode} rebuilds
 * the prefix faithfully. Multi-message (streaming) bodies abdicate for now.
 */
public final class RpcFrameStage implements Stage {
    @Override public String id() { return "grpc"; }
    @Override public Kind kind() { return Kind.FRAMING; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        if (in == null || in.length < 5) return false;
        int flag = in[0] & 0xff;
        if (flag > 1) return false;
        long len = Be32.readU32(in, 1);
        return len >= 0 && 5 + len == in.length; // exactly one frame
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        if (in == null || in.length < 5) throw new CodecException("grpc: too short for a frame");
        int flag = in[0] & 0xff;
        if (flag > 1) throw new CodecException("grpc: unexpected flag byte " + flag);
        long len = Be32.readU32(in, 1);
        if (5 + len > in.length) throw new CodecException("grpc: frame length exceeds body");
        if (5 + len != in.length) throw new CodecException("grpc: multi-message streaming not supported");
        byte[] payload = Arrays.copyOfRange(in, 5, (int) (5 + len));
        Node n = Node.bytes(payload);
        n.meta.put("grpc.flag", flag & 1);
        return n;
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        Object f = edited.meta.get("grpc.flag");
        int flag = (f instanceof Integer) ? ((Integer) f) & 1 : 0;
        byte[] payload = edited.bytes;
        ByteArrayOutputStream out = new ByteArrayOutputStream(payload.length + 5);
        out.write(flag);
        Be32.writeU32(out, payload.length);
        out.write(payload, 0, payload.length);
        return out.toByteArray();
    }

    @Override public boolean canEncode() { return true; }
}
