package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;

public class CodecWebSocketEditorProvider implements WebSocketMessageEditorProvider {
    private final MontoyaApi api;

    public CodecWebSocketEditorProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext creationContext) {
        boolean readOnly = creationContext.editorMode() == EditorMode.READ_ONLY;
        return new CodecWebSocketEditor(api, readOnly);
    }
}
