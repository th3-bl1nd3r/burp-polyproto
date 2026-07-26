package burp.polyproto.stage.framing;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;

import java.util.Base64;

/**
 * gRPC-Web text (Content-Type application/grpc-web-text): the entire binary gRPC-Web stream is
 * base64-encoded. Base64-decode, then reuse {@link GrpcWebStage} framing; re-encode base64 on edit.
 */
public final class GrpcWebTextStage extends GrpcWebStage {
    @Override public String id() { return "grpc-web-text"; }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        byte[] bin;
        try {
            bin = Base64.getMimeDecoder().decode(in);
        } catch (Exception e) {
            throw new CodecException("grpc-web-text: invalid base64", e);
        }
        return decode(bin, true); // marks grpcweb.text = true so encode() re-base64s
    }
}
