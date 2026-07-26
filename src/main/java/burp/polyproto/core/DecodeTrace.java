package burp.polyproto.core;

import burp.polyproto.stage.Stage;
import burp.polyproto.stage.StageMeta;

import java.util.ArrayList;
import java.util.List;

/**
 * The ordered record of how one message was decoded, so {@link Pipeline#encode} can reverse it
 * exactly. {@link #steps} and {@link #executed} are parallel (one entry per stage that actually
 * ran — optional stages that were skipped do not appear).
 */
public final class DecodeTrace {
    public final List<StageMeta> steps = new ArrayList<>();
    public final List<Stage> executed = new ArrayList<>();
    public String terminalFormat;   // "protobuf" | "json" | "form" | "text" | "raw" | "bytes"
    public String plaintext;        // the editable terminal text
    public boolean faithful = true; // false once any executed coding stage cannot re-encode
}
