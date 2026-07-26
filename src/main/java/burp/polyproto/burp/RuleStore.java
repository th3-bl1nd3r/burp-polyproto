package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.polyproto.rule.Rule;
import burp.polyproto.rule.RuleCodec;
import burp.polyproto.rule.RuleRegistry;
import burp.polyproto.rule.Ruleset;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Loads the ruleset (saved preference, else bundled builtins) and persists edits. */
public final class RuleStore {
    public static final String PREF_KEY = "polyproto.rules.v1";

    /** Load rules into the live registry: saved copy if present, otherwise the bundled builtins. */
    public static void loadInto(MontoyaApi api) {
        List<Rule> rules;
        String saved = null;
        try { saved = api.persistence().preferences().getString(PREF_KEY); } catch (Exception ignore) { }
        if (saved != null && !saved.isBlank()) {
            try { rules = RuleCodec.fromJson(saved).rules; }
            catch (Exception e) { api.logging().logToError("PolyProto: bad saved rules, using builtins", e); rules = builtins(api); }
        } else {
            rules = builtins(api);
        }
        RuleRegistry.get().set(rules);
        api.logging().logToOutput("PolyProto: loaded " + rules.size() + " rules"
                + (saved != null && !saved.isBlank() ? " (saved)" : " (builtins)"));
    }

    /** Persist the current registry snapshot as a preference (survives restarts, cross-project). */
    public static void save(MontoyaApi api) {
        try {
            Ruleset rs = new Ruleset();
            rs.rules.addAll(RuleRegistry.get().snapshot());
            api.persistence().preferences().setString(PREF_KEY, RuleCodec.toJson(rs));
        } catch (Exception e) {
            api.logging().logToError("PolyProto: save rules failed", e);
        }
    }

    public static List<Rule> builtins(MontoyaApi api) {
        try (InputStream in = RuleStore.class.getResourceAsStream("/codec/builtins.json")) {
            if (in == null) { api.logging().logToError("PolyProto: builtins.json missing"); return List.of(); }
            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return RuleCodec.fromJson(json).rules;
        } catch (Exception e) {
            api.logging().logToError("PolyProto: load builtins failed", e);
            return List.of();
        }
    }

    private RuleStore() {}
}
