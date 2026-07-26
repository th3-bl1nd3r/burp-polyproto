package burp.polyproto.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-message decode/encode context, populated from the matched rule's action before the
 * pipeline runs. Stages read what they need (proprietary Content-Encoding aliases, the
 * per-message gRPC codec header, the schema pack to overlay, ...). Kept dependency-light on
 * purpose; the engine wires in the StageRegistry / SchemaPackStore references as they are added.
 */
public final class PipelineCtx {
    public Msg msg;
    public Direction direction;

    /** Proprietary Content-Encoding header aliases, e.g. ["X-Bd-Content-Encoding"]. */
    public List<String> encodingHeaders = new ArrayList<>();
    /** gRPC/Connect per-message codec header name, e.g. "grpc-encoding". */
    public String perMessageCodecHeader;
    /** Named protobuf schema overlay / envelope descriptor. */
    public String schemaPack;
    /** Schema selection expression, e.g. "byDirection:REQUEST=Request,RESPONSE=Response". */
    public String schemaSelect;

    /** Free-form scratch shared across stages within one decode. */
    public final Map<String, Object> attrs = new HashMap<>();

    public PipelineCtx() {}

    public PipelineCtx(Msg msg) {
        this.msg = msg;
        this.direction = msg != null ? msg.direction() : null;
    }
}
