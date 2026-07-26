package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.polyproto.core.CodecEngine;
import burp.polyproto.core.DecodeResult;
import burp.polyproto.ui.DecoderPanel;

import java.awt.Component;

/**
 * Editable "Decoded" tab for HTTP request bodies. Decodes the wire body to editable text; on send,
 * re-encodes (reversing every layer) so you can tamper with a compressed/framed/protobuf body and
 * replay it. Signature recomputation is layered in with the rule engine.
 */
public class CodecRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final MontoyaApi api;
    private final CodecEngine engine;
    private final DecoderPanel panel;
    private HttpRequestResponse rr;
    private DecodeResult result;

    public CodecRequestEditor(MontoyaApi api, CodecEngine engine, boolean editable) {
        this.api = api;
        this.engine = engine;
        this.panel = new DecoderPanel(api, editable);
    }

    @Override
    public HttpRequest getRequest() {
        if (rr == null) return null;
        HttpRequest orig = rr.request();
        if (result == null || !result.editable || !panel.isModified()) return orig;
        try {
            byte[] newBody = engine.encode(result, panel.getText());
            HttpRequest req = orig.withBody(ByteArray.byteArray(newBody));
            if (!result.faithful) {
                // a coding layer was dropped to identity — remove the now-wrong encoding headers
                req = req.withRemovedHeader("Content-Encoding");
                if (req.hasHeader("X-Bd-Content-Encoding")) req = req.withRemovedHeader("X-Bd-Content-Encoding");
            }
            return req;
        } catch (Exception e) {
            api.logging().logToError("PolyProto getRequest", e);
            return orig;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.rr = requestResponse;
        try {
            result = engine.decode(MsgAdapter.request(requestResponse.request()));
            panel.show(result);
        } catch (Exception e) {
            result = null;
            api.logging().logToError("PolyProto decode(request)", e);
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            HttpRequest req = requestResponse.request();
            if (req == null || req.body().length() == 0) return false;
            MsgAdapter m = MsgAdapter.request(req);
            return engine.detector().looksDecodable(m.body(), m);
        } catch (Exception e) {
            return false;
        }
    }

    @Override public String caption() { return "Decoded"; }
    @Override public Component uiComponent() { return panel.getComponent(); }
    @Override public Selection selectedData() { return null; }
    @Override public boolean isModified() { return panel.isModified(); }
}
