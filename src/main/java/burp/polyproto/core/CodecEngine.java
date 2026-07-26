package burp.polyproto.core;

import burp.polyproto.rule.Action;
import burp.polyproto.rule.Labels;
import burp.polyproto.rule.Rule;
import burp.polyproto.rule.RuleRegistry;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.StageMeta;
import burp.polyproto.stage.StageRegistry;

import java.util.List;

/**
 * Facade: resolve the matching rule (or auto-detect), compile a {@link Pipeline}, decode to editable
 * text, and reverse on edit. {@link #decode(Msg)} is the rule-aware entry the editors use;
 * {@link #decode(Msg, List)} bypasses rules for tests / explicit pipelines.
 */
public final class CodecEngine {
    private final StageRegistry reg;
    private final Detector detector;
    private final RuleRegistry rules; // may be null (pure auto)

    public CodecEngine(StageRegistry reg, Detector detector) { this(reg, detector, null); }

    public CodecEngine(StageRegistry reg, Detector detector, RuleRegistry rules) {
        this.reg = reg;
        this.detector = detector;
        this.rules = rules;
    }

    /** Rule-aware decode: the highest-priority matching rule selects the pipeline/schema/label. */
    public DecodeResult decode(Msg msg) {
        Rule rule = rules != null ? rules.firstMatch(msg) : null;
        return decodeWith(msg, rule);
    }

    /** Explicit-pipeline decode (no rules). forced null/["auto"] => auto-detect. */
    public DecodeResult decode(Msg msg, List<String> forced) {
        DecodeResult r = new DecodeResult();
        PipelineCtx ctx = new PipelineCtx(msg);
        r.ctx = ctx;
        List<String> tokens = isAuto(forced) ? detector.sniff(msg.body(), msg) : forced;
        run(r, msg, ctx, tokens);
        return r;
    }

    private DecodeResult decodeWith(Msg msg, Rule rule) {
        DecodeResult r = new DecodeResult();
        PipelineCtx ctx = new PipelineCtx(msg);
        r.ctx = ctx;

        Action a = rule != null ? rule.action : null;
        if (a != null) {
            ctx.schemaPack = a.schemaPack;
            ctx.schemaSelect = a.schemaSelect;
            if (a.encodingHeaders != null) ctx.encodingHeaders = a.encodingHeaders;
            ctx.perMessageCodecHeader = a.perMessageCodecHeader;
        }

        List<String> forced = a != null ? a.forcePipeline : null;
        List<String> tokens = isAuto(forced) ? detector.sniff(msg.body(), msg) : forced;
        run(r, msg, ctx, tokens);

        r.matchedRuleName = rule != null ? (rule.name != null ? rule.name : rule.id) : null;
        if (a != null && a.label != null && r.text != null) {
            try { r.label = Labels.extract(a.label, msg, r.text); } catch (Exception ignore) { }
        }
        return r;
    }

    private void run(DecodeResult r, Msg msg, PipelineCtx ctx, List<String> tokens) {
        Pipeline p = new PipelineCompiler(reg).compile(tokens, ctx);
        r.pipeline = p;
        try {
            DecodeTrace tr = p.decode(msg.body(), ctx);
            r.trace = tr;
            r.text = tr.plaintext;
            r.terminalFormat = tr.terminalFormat;
            r.faithful = tr.faithful;
            r.breadcrumb = String.join(" › ", p.breadcrumbTokens(tr));
            boolean readonly = Boolean.TRUE.equals(readonlyFlag(tr));
            r.editable = !readonly && !"raw".equals(tr.terminalFormat) && !"bytes".equals(tr.terminalFormat);
            for (StageMeta sm : tr.steps) {
                Object nt = sm.params.get("note");
                if (nt != null) r.note = (r.note == null ? "" : r.note + " | ") + nt;
            }
            if (!tr.steps.isEmpty()) {
                java.util.Map<String, Object> last = tr.steps.get(tr.steps.size() - 1).params;
                if (last.get("proto.bytes") instanceof byte[]) r.terminalBytes = (byte[]) last.get("proto.bytes");
                if (last.get("proto.schema") instanceof burp.polyproto.protobuf.ProtoSchema)
                    r.schema = (burp.polyproto.protobuf.ProtoSchema) last.get("proto.schema");
            }
            if (!tr.faithful) r.note = (r.note == null ? "" : r.note + " | ")
                    + "non-faithful re-encode (a coding layer drops to identity on edit)";
        } catch (Exception e) {
            r.text = "[polyproto] decode failed: " + e.getMessage();
            r.note = String.valueOf(e);
            r.editable = false;
        }
    }

    private static Object readonlyFlag(DecodeTrace tr) {
        if (tr.steps.isEmpty()) return null;
        return tr.steps.get(tr.steps.size() - 1).params.get("readonly");
    }

    private static boolean isAuto(List<String> forced) {
        return forced == null || forced.isEmpty() || (forced.size() == 1 && "auto".equals(forced.get(0)));
    }

    public byte[] encode(DecodeResult prior, String editedText) throws CodecException {
        if (prior == null || prior.pipeline == null || prior.trace == null) {
            throw new CodecException("no prior decode to reverse");
        }
        return prior.pipeline.encode(editedText, prior.trace, prior.ctx);
    }

    public Detector detector() { return detector; }
    public StageRegistry registry() { return reg; }
}
