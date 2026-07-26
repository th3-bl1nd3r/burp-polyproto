package burp.polyproto.stage;

import java.util.HashMap;
import java.util.Map;

/** One recorded peel step: which stage ran and the params its encode() needs to reverse it. */
public final class StageMeta {
    public final String stageId;
    public final Map<String, Object> params = new HashMap<>();

    public StageMeta(String stageId) { this.stageId = stageId; }

    public StageMeta put(String k, Object v) { params.put(k, v); return this; }

    @Override public String toString() { return stageId; }
}
