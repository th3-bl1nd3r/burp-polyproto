package burp.polyproto.stage.coding;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

/** No-op passthrough. Lowest priority; never auto-selected, only used as an explicit token/fallback. */
public final class IdentityStage implements Stage {
    @Override public String id() { return "identity"; }
    @Override public Kind kind() { return Kind.CODING; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return true; }
    @Override public Node decode(byte[] in, PipelineCtx ctx) { return Node.bytes(in); }
    @Override public byte[] encode(Node edited, PipelineCtx ctx) { return edited.bytes; }
    @Override public boolean canEncode() { return true; }
}
