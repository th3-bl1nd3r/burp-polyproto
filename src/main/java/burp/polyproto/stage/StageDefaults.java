package burp.polyproto.stage;

import burp.polyproto.stage.coding.BrotliStage;
import burp.polyproto.stage.coding.DeflateStage;
import burp.polyproto.stage.coding.GzipStage;
import burp.polyproto.stage.coding.IdentityStage;
import burp.polyproto.stage.coding.ZstdStage;
import burp.polyproto.stage.format.AutoFormatStage;
import burp.polyproto.stage.format.FormJsonStage;
import burp.polyproto.stage.format.FormStage;
import burp.polyproto.stage.format.JsonStage;
import burp.polyproto.stage.format.ProtobufStage;
import burp.polyproto.stage.format.RawStage;
import burp.polyproto.stage.format.TextStage;
import burp.polyproto.stage.format.XmlStage;
import burp.polyproto.stage.framing.ChunkedStage;
import burp.polyproto.stage.framing.GrpcWebStage;
import burp.polyproto.stage.framing.GrpcWebTextStage;
import burp.polyproto.stage.framing.RpcFrameStage;

/** Registers the built-in stages available in this build. Vendor packs add more via the Pack SPI. */
public final class StageDefaults {

    public static StageRegistry create() {
        StageRegistry r = new StageRegistry();

        // framing
        r.register("grpc-web-text", 62, GrpcWebTextStage::new);
        r.register("grpc-web", 61, GrpcWebStage::new);
        r.register("grpc", 60, RpcFrameStage::new);
        r.register("dechunk", 50, ChunkedStage::new);

        // content-coding (identity lowest so it is never auto-selected;
        // brotli negative so it is never blind-detected — only via rule/header)
        r.register("zstd", 45, ZstdStage::new);
        r.register("gzip", 40, GzipStage::new);
        r.register("deflate", 35, DeflateStage::new);
        r.register("br", -50, BrotliStage::new);
        r.register("identity", -100, IdentityStage::new);

        // format (priority = auto-detect preference among printable/binary)
        r.register("form+json", 35, FormJsonStage::new);
        r.register("json", 30, JsonStage::new);
        r.register("xml", 25, XmlStage::new);
        r.register("form", 20, FormStage::new);
        r.register("protobuf", 10, ProtobufStage::new);
        r.register("text", 5, TextStage::new);
        r.register("auto-format", 0, AutoFormatStage::new);
        r.register("raw", -100, RawStage::new);

        return r;
    }

    private StageDefaults() {}
}
