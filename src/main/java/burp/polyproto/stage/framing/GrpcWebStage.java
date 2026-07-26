package burp.polyproto.stage.framing;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * gRPC-Web (binary) framing (Content-Type application/grpc-web). Like gRPC but the last frame is a
 * TRAILER (flag MSB 0x80) carrying ASCII "grpc-status: 0 ..." headers instead of a message. Yields
 * the first data frame's payload (still compressed if flagged), and preserves the trailer verbatim
 * for re-encode. The trailer text is surfaced as a note.
 */
public class GrpcWebStage implements Stage {
    @Override public String id() { return "grpc-web"; }
    @Override public Kind kind() { return Kind.FRAMING; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return false; } // content-type driven

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        return decode(in, false);
    }

    /** Shared by the -text variant after it base64-decodes. */
    protected Node decode(byte[] in, boolean text) throws CodecException {
        List<GrpcWeb.F> frames = GrpcWeb.parse(in);
        if (frames.isEmpty()) throw new CodecException("grpc-web: no frames");
        GrpcWeb.F data = null;
        String trailer = null;
        for (GrpcWeb.F f : frames) {
            if (f.trailer()) trailer = new String(f.data, StandardCharsets.US_ASCII);
            else if (data == null) data = f;
        }
        if (data == null) throw new CodecException("grpc-web: no data frame");
        Node n = Node.bytes(data.data);
        n.meta.put("grpcweb.flag", data.flag & 1);
        n.meta.put("grpcweb.text", text);
        if (trailer != null) {
            n.meta.put("grpcweb.trailer", trailer);
            n.meta.put("note", "grpc-web trailer: " + trailer.trim().replace("\r\n", "  "));
        }
        return n;
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        int flag = edited.meta.get("grpcweb.flag") instanceof Integer ? ((Integer) edited.meta.get("grpcweb.flag")) & 1 : 0;
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] dataFrame = GrpcWeb.frame(flag, edited.bytes);
        o.write(dataFrame, 0, dataFrame.length);
        Object trailer = edited.meta.get("grpcweb.trailer");
        if (trailer instanceof String) {
            byte[] tf = GrpcWeb.frame(0x80, ((String) trailer).getBytes(StandardCharsets.US_ASCII));
            o.write(tf, 0, tf.length);
        }
        byte[] bin = o.toByteArray();
        return Boolean.TRUE.equals(edited.meta.get("grpcweb.text"))
                ? java.util.Base64.getEncoder().encode(bin) : bin;
    }

    @Override public boolean canEncode() { return true; }
}
