package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;

/**
 * Single source of truth for classifying a decompressed buffer into a terminal format id.
 * Used by both the {@code Detector} (auto-detect) and {@link AutoFormatStage} so they never drift.
 *
 * <p>Ordering matters: the more specific printable formats (xml, json, form+json, form) are tried
 * first; protobuf is tried BEFORE plain text so a string-heavy protobuf (emails, names, URLs — which
 * is >90% printable) is not mistaken for text; raw is the binary fallback.
 */
public final class FormatSniffer {

    public static String classify(byte[] b, PipelineCtx ctx) {
        if (b == null || b.length == 0) return "raw";
        PipelineCtx c = ctx != null ? ctx : new PipelineCtx();
        if (Protobuf.asPrintable(b) != null) {
            if (new XmlStage().sniff(b, c)) return "xml";
            if (JsonStage.looksJson(b)) return "json";
            if (new FormJsonStage().sniff(b, c)) return "form+json";
            if (FormStage.looksForm(b)) return "form";
            if (ProtobufStage.isProtobuf(b)) return "protobuf";
            return "text";
        }
        if (ProtobufStage.isProtobuf(b)) return "protobuf";
        return "raw";
    }

    private FormatSniffer() {}
}
