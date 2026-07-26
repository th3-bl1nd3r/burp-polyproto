package burp.polyproto.rule;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The whole user-editable document: rules plus (opaque here) schema-pack and dictionary definitions
 * that the pack layer consumes. Kept as raw maps so this package stays independent of pack classes.
 */
public final class Ruleset {
    public int version = 1;
    public List<Rule> rules = new ArrayList<>();
    public Map<String, Object> schemaPacks = new LinkedHashMap<>();
    public Map<String, String> dictionaries = new LinkedHashMap<>();
}
