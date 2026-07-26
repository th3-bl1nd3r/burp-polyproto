package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.polyproto.core.CodecEngine;
import burp.polyproto.core.DecodeResult;
import burp.polyproto.ui.DecoderPanel;

import java.awt.Component;

/** Read-only "Decoded" tab for HTTP response bodies. */
public class CodecResponseEditor implements ExtensionProvidedHttpResponseEditor {
    private final MontoyaApi api;
    private final CodecEngine engine;
    private final DecoderPanel panel;
    private HttpRequestResponse rr;

    public CodecResponseEditor(MontoyaApi api, CodecEngine engine) {
        this.api = api;
        this.engine = engine;
        this.panel = new DecoderPanel(api, false);
    }

    @Override
    public HttpResponse getResponse() { return rr != null ? rr.response() : null; }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.rr = requestResponse;
        try {
            DecodeResult r = engine.decode(
                    MsgAdapter.response(requestResponse.response(), requestResponse.request()));
            panel.show(r);
        } catch (Exception e) {
            api.logging().logToError("PolyProto decode(response)", e);
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            HttpResponse resp = requestResponse.response();
            if (resp == null || resp.body().length() == 0) return false;
            MsgAdapter m = MsgAdapter.response(resp, requestResponse.request());
            return engine.detector().looksDecodable(m.body(), m);
        } catch (Exception e) {
            return false;
        }
    }

    @Override public String caption() { return "Decoded"; }
    @Override public Component uiComponent() { return panel.getComponent(); }
    @Override public Selection selectedData() { return null; }
    @Override public boolean isModified() { return false; }
}
