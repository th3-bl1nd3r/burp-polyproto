package burp.polyproto.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.polyproto.core.CodecEngine;
import burp.polyproto.core.Detector;
import burp.polyproto.pack.SchemaPacks;
import burp.polyproto.pack.TikTokPack;
import burp.polyproto.rule.RuleRegistry;
import burp.polyproto.stage.StageDefaults;
import burp.polyproto.stage.StageRegistry;

/**
 * PolyProto entry point. A vendor-neutral request/response decoder: auto-detects content-encoding
 * (gzip/zstd/deflate/brotli), HTTP chunked framing, and body format (protobuf/JSON/form/form+json/
 * xml) across ALL hosts, and lets you edit + replay. Rule engine, vendor packs (TikTok/Meta field
 * names, Frontier WebSocket), and the Rules-manager tab are layered on next.
 */
public class CodecExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("PolyProto");

        TikTokPack.install(SchemaPacks.get());
        RuleStore.loadInto(api);

        StageRegistry registry = StageDefaults.create();
        CodecEngine engine = new CodecEngine(registry, new Detector(registry), RuleRegistry.get());

        api.userInterface().registerHttpRequestEditorProvider(new CodecRequestEditorProvider(api, engine));
        api.userInterface().registerHttpResponseEditorProvider(new CodecResponseEditorProvider(api, engine));
        api.userInterface().registerWebSocketMessageEditorProvider(new CodecWebSocketEditorProvider(api));
        api.http().registerHttpHandler(new RuleHttpHandler());
        api.userInterface().registerSuiteTab("PolyProto", new burp.polyproto.ui.RulesTab(api));

        api.logging().logToOutput(
                "PolyProto loaded. 'Decoded' tab auto-decodes gzip/zstd/deflate/brotli + HTTP-chunked "
                + "+ gRPC + protobuf/JSON/form/form+json/xml across all hosts, with lossless edit+replay. "
                + "Rule-driven (host/path/header → pipeline, label, header-rewrite). Vendor field-name "
                + "packs, Frontier WS, and the Rules tab are next.");
    }
}
