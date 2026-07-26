package burp.polyproto.rule;

import java.util.List;

/** What to do when a {@link Rule} matches: how to decode, annotate, rewrite, and sign. */
public final class Action {
    public List<String> forcePipeline;     // null or ["auto"] => auto-detect
    public List<String> encodingHeaders;   // proprietary Content-Encoding aliases, e.g. X-Bd-Content-Encoding
    public String perMessageCodecHeader;   // grpc-encoding / Connect-Content-Encoding
    public String schemaPack;              // named protobuf overlay / envelope descriptor
    public String schemaSelect;            // "byDirection:REQUEST=Request,RESPONSE=Response"
    public List<HeaderRewrite> rewriteHeader;
    public SigSpec recomputeSig;
    public LabelSpec label;
}
