package burp.polyproto.core;

import burp.polyproto.protobuf.ProtoSchema;

/** What the editor tab shows for one message, plus everything {@link CodecEngine#encode} needs. */
public final class DecodeResult {
    public Pipeline pipeline;
    public DecodeTrace trace;
    public PipelineCtx ctx;

    // when the terminal format is protobuf: the decoded message bytes + resolved name overlay,
    // so the panel can build the foldable tree and re-decode nested bytes fields.
    public byte[] terminalBytes;
    public ProtoSchema schema;

    public String text;             // editable terminal text (or an error string)
    public String terminalFormat;   // resolved format id
    public String breadcrumb;       // "dechunk › gzip › protobuf"
    public String label;            // rule-extracted label, or null
    public boolean faithful = true; // false => identity fallback on edit
    public boolean editable = true; // false for raw/undecodable or read-only contexts
    public String note;             // diagnostic (e.g. decode failure)
    public String matchedRuleName;  // name of the rule that selected the pipeline, or null (auto)
}
