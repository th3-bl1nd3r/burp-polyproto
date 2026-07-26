package burp.polyproto.protobuf;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Lightweight protobuf field-name schema used to overlay human-readable names onto the
 * schema-less wire decode. Only the fields we know (from RE) are named; everything else
 * still renders generically by tag number.
 */
public final class ProtoSchema {
    public final String name;
    private final Map<Integer, String> names = new LinkedHashMap<>();
    private final Map<Integer, ProtoSchema> nested = new HashMap<>();

    public ProtoSchema(String name) { this.name = name; }

    /** scalar / string field */
    public ProtoSchema f(int tag, String fieldName) {
        names.put(tag, fieldName);
        return this;
    }

    /** message field pointing at a nested schema */
    public ProtoSchema f(int tag, String fieldName, ProtoSchema sub) {
        names.put(tag, fieldName);
        nested.put(tag, sub);
        return this;
    }

    public String name(int tag) { return names.get(tag); }
    public ProtoSchema nested(int tag) { return nested.get(tag); }
}
