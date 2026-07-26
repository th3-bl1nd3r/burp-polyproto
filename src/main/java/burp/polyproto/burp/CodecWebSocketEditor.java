package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.polyproto.frontier.Frame;
import burp.polyproto.frontier.FrameText;
import burp.polyproto.ui.CodeView;

import java.awt.Component;

/**
 * "Frontier" editor for Frontier WebSocket messages. Decodes each binary frame into an
 * editable, syntax-colored text form; when the user sends (WS Repeater), getMessage()
 * re-encodes it to a valid protobuf Frame. Frontier frames are not individually signed,
 * so edits are accepted by the server. Vendor-neutral: any protobuf WS frame that parses
 * as a Frame is offered, regardless of host.
 */
public class CodecWebSocketEditor implements ExtensionProvidedWebSocketMessageEditor {
    private final CodeView view;
    private byte[] original = new byte[0];

    public CodecWebSocketEditor(MontoyaApi api, boolean readOnly) {
        this.view = new CodeView(api, !readOnly);
    }

    @Override
    public ByteArray getMessage() {
        try {
            Frame f = FrameText.parse(view.getText());
            return ByteArray.byteArray(f.encode());
        } catch (Exception e) {
            return ByteArray.byteArray(original);
        }
    }

    @Override
    public void setMessage(WebSocketMessage message) {
        original = message.payload().getBytes();
        String text;
        try {
            text = FrameText.toText(Frame.parse(original));
        } catch (Exception e) {
            text = "[polyproto] not a Frontier frame: " + e;
        }
        view.setText(text);
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage message) {
        try {
            byte[] p = message.payload().getBytes();
            if (p.length == 0) return false;
            Frame f = Frame.parse(p); // throws if not protobuf
            return f.service != 0 || f.method != 0 || !f.headers.isEmpty() || f.payloadEncoding != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Override public String caption() { return "Frontier"; }
    @Override public Component uiComponent() { return view.getComponent(); }
    @Override public Selection selectedData() { return null; }
    @Override public boolean isModified() { return view.isModified(); }
}
