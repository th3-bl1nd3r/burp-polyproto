package burp.polyproto.core;

import burp.polyproto.stage.Stage;
import burp.polyproto.stage.StageRegistry;

import java.util.ArrayList;
import java.util.List;

/** Turns a resolved token list into a runnable {@link Pipeline}. Unknown tokens are skipped. */
public final class PipelineCompiler {
    private final StageRegistry reg;

    public PipelineCompiler(StageRegistry reg) { this.reg = reg; }

    public Pipeline compile(List<String> tokens, PipelineCtx ctx) {
        List<Stage> stages = new ArrayList<>();
        List<String> resolved = new ArrayList<>();
        List<Boolean> opt = new ArrayList<>();
        for (String tok : tokens) {
            Stage s = reg.resolve(tok, ctx);
            if (s == null) continue;
            stages.add(s);
            resolved.add(tok);
            opt.add(tok.endsWith("?"));
        }
        boolean[] optional = new boolean[stages.size()];
        for (int i = 0; i < optional.length; i++) optional[i] = opt.get(i);
        return new Pipeline(resolved, stages, optional);
    }
}
