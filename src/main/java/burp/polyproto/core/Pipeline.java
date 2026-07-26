package burp.polyproto.core;

import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import burp.polyproto.stage.StageMeta;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A compiled ordered chain of stages (outer→inner). {@link #decode} peels layer by layer,
 * recording a {@link DecodeTrace}; {@link #encode} reverses that trace exactly. Optional ("?")
 * stages are skipped at decode time when their sniff() misses.
 */
public final class Pipeline {
    public final List<String> tokens;
    final List<Stage> stages;
    final boolean[] optional;

    Pipeline(List<String> tokens, List<Stage> stages, boolean[] optional) {
        this.tokens = tokens;
        this.stages = stages;
        this.optional = optional;
    }

    public DecodeTrace decode(byte[] wire, PipelineCtx ctx) throws CodecException {
        DecodeTrace tr = new DecodeTrace();
        byte[] cur = wire == null ? new byte[0] : wire;
        for (int i = 0; i < stages.size(); i++) {
            Stage s = stages.get(i);
            if (optional[i] && !s.sniff(cur, ctx)) continue;
            Node node = s.decode(cur, ctx);
            String stepId = node.type == Node.Type.TEXT && node.formatId != null ? node.formatId : s.id();
            StageMeta sm = new StageMeta(stepId);
            sm.params.putAll(node.meta);
            tr.steps.add(sm);
            tr.executed.add(s);
            if (!s.canEncode()) tr.faithful = false;

            if (node.type == Node.Type.TEXT) {
                tr.plaintext = node.text;
                tr.terminalFormat = node.formatId;
                return tr;
            } else if (node.type == Node.Type.BYTES) {
                cur = node.bytes;
            } else {
                throw new CodecException("framed (multi-message) decoding not wired yet");
            }
        }
        // Ran out of stages without a terminal format: surface the remaining bytes.
        tr.plaintext = new String(cur, StandardCharsets.UTF_8);
        tr.terminalFormat = "bytes";
        return tr;
    }

    public byte[] encode(String editedText, DecodeTrace tr, PipelineCtx ctx) throws CodecException {
        int n = tr.executed.size();
        if (n == 0) return editedText.getBytes(StandardCharsets.UTF_8);

        byte[] cur;
        int startIdx;
        if ("bytes".equals(tr.terminalFormat)) {
            cur = editedText.getBytes(StandardCharsets.UTF_8);
            startIdx = n - 1;
        } else {
            Stage term = tr.executed.get(n - 1);
            Node tn = Node.text(editedText, tr.terminalFormat);
            tn.meta.putAll(tr.steps.get(n - 1).params);
            cur = term.encode(tn, ctx);
            startIdx = n - 2;
        }
        for (int i = startIdx; i >= 0; i--) {
            Stage s = tr.executed.get(i);
            if (!s.canEncode()) continue; // identity fallback: this layer is dropped
            Node bn = Node.bytes(cur);
            bn.meta.putAll(tr.steps.get(i).params);
            cur = s.encode(bn, ctx);
        }
        return cur;
    }

    /** Executed stage/format ids for the breadcrumb, e.g. [dechunk, gzip, protobuf]. */
    public List<String> breadcrumbTokens(DecodeTrace tr) {
        List<String> out = new ArrayList<>();
        for (StageMeta sm : tr.steps) out.add(sm.stageId);
        return out;
    }
}
