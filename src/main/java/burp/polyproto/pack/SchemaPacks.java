package burp.polyproto.pack;

import burp.polyproto.core.Direction;
import burp.polyproto.protobuf.ProtoSchema;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of named schema overlays and WebSocket envelope descriptors, consulted by
 * {@code ProtobufStage} / {@code EnvelopeStage} when a rule sets a {@code schemaPack}. A singleton
 * so stages can reach it without threading it through every call.
 */
public final class SchemaPacks {
    private static final SchemaPacks INSTANCE = new SchemaPacks();
    public static SchemaPacks get() { return INSTANCE; }

    private final Map<String, EnumMap<Direction, ProtoSchema>> protos = new ConcurrentHashMap<>();
    private final Map<String, EnvelopeDescriptor> envelopes = new ConcurrentHashMap<>();

    public void putProto(String pack, Direction dir, ProtoSchema schema) {
        protos.computeIfAbsent(pack, k -> new EnumMap<>(Direction.class)).put(dir, schema);
    }

    /** Overlay for a pack in the given direction, falling back to a BOTH-direction schema. */
    public ProtoSchema proto(String pack, Direction dir) {
        if (pack == null) return null;
        EnumMap<Direction, ProtoSchema> m = protos.get(pack);
        if (m == null) return null;
        ProtoSchema s = dir != null ? m.get(dir) : null;
        return s != null ? s : m.get(Direction.BOTH);
    }

    public void putEnvelope(String pack, EnvelopeDescriptor d) { envelopes.put(pack, d); }
    public EnvelopeDescriptor envelope(String pack) { return pack == null ? null : envelopes.get(pack); }

    public boolean hasProto(String pack) { return pack != null && protos.containsKey(pack); }
}
