package burp.polyproto.core;

import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import burp.polyproto.stage.StageRegistry;
import burp.polyproto.stage.coding.DeflateStage;
import burp.polyproto.stage.coding.GzipStage;
import burp.polyproto.stage.coding.ZstdStage;
import burp.polyproto.stage.format.FormJsonStage;
import burp.polyproto.stage.format.FormatSniffer;
import burp.polyproto.stage.framing.ChunkedStage;
import burp.polyproto.stage.framing.GrpcWebStage;
import burp.polyproto.stage.framing.GrpcWebTextStage;
import burp.polyproto.stage.framing.RpcFrameStage;
import burp.polyproto.util.Chunked;

import java.util.ArrayList;
import java.util.List;

/**
 * Auto-detect: produce the outer→inner token list for a wire buffer when no rule pins one.
 * Magic-first, then structural. Content-codings with no reliable magic (brotli, raw-deflate)
 * are intentionally NOT blind-detected here — only a rule/header selects them.
 */
public final class Detector {
    private final StageRegistry reg;

    public Detector(StageRegistry reg) { this.reg = reg; }

    public List<String> sniff(byte[] wire, Msg msg) {
        List<String> tokens = new ArrayList<>();
        byte[] cur = wire == null ? new byte[0] : wire;
        PipelineCtx ctx = new PipelineCtx(msg);

        // 1. framing: gRPC (by Content-Type) or HTTP chunked (structural). May yield inner bytes.
        Stage framing = pickFraming(cur, msg);
        if (framing != null) {
            try {
                Node n = framing.decode(cur, ctx);
                tokens.add(framing.id());
                if (n.type == Node.Type.TEXT) return tokens;   // framing was terminal
                if (n.type == Node.Type.BYTES) cur = n.bytes;
            } catch (CodecException e) {
                tokens.clear();                                 // framing didn't apply; keep original bytes
            }
        }

        // 2. content-encoding, peeled by magic (loop to catch stacked layers, e.g. hidden gzip).
        for (int i = 0; i < 6; i++) {
            Stage s = codingByMagic(cur, ctx);
            if (s == null) break;
            try {
                Node n = s.decode(cur, ctx);
                if (n.type != Node.Type.BYTES) break;
                cur = n.bytes;
                tokens.add(s.id());
            } catch (CodecException e) {
                break; // e.g. a zstd dictionary frame — leave it for a rule to handle
            }
        }

        // 3. terminal format
        tokens.add(sniffFormat(cur, ctx));
        return tokens;
    }

    /** gRPC framing when the Content-Type says so, else HTTP chunked when the body is chunked. */
    private Stage pickFraming(byte[] cur, Msg msg) {
        String ct = msg != null && msg.contentType() != null ? msg.contentType().toLowerCase() : "";
        if (ct.contains("application/grpc-web-text")) return new GrpcWebTextStage();
        if (ct.contains("application/grpc-web")) return new GrpcWebStage();
        if (ct.contains("application/grpc")) return new RpcFrameStage();
        if (Chunked.dechunk(cur) != null) return new ChunkedStage();
        return null;
    }

    /** Next content-coding by unambiguous magic only (never brotli / raw-deflate). */
    private Stage codingByMagic(byte[] cur, PipelineCtx ctx) {
        GzipStage gz = new GzipStage();
        if (gz.sniff(cur, ctx)) return gz;
        ZstdStage zs = new ZstdStage();
        if (zs.sniff(cur, ctx)) return zs;
        DeflateStage df = new DeflateStage(); // sniff verifies a real zlib stream
        if (df.sniff(cur, ctx)) return df;
        return null;
    }

    public String sniffFormat(byte[] b) { return FormatSniffer.classify(b, new PipelineCtx()); }

    /** Classify a decompressed buffer via the shared {@link FormatSniffer}. */
    public String sniffFormat(byte[] b, PipelineCtx ctx) { return FormatSniffer.classify(b, ctx); }

    public boolean looksDecodable(byte[] wire, Msg msg) {
        if (wire == null || wire.length == 0) return false;
        List<String> t = sniff(wire, msg);
        String fmt = t.isEmpty() ? "raw" : t.get(t.size() - 1);
        return t.size() > 1 || !"raw".equals(fmt); // peeled a layer, or a known format
    }
}
