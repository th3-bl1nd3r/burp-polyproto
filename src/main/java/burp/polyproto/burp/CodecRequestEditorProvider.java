package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.polyproto.core.CodecEngine;

public class CodecRequestEditorProvider implements HttpRequestEditorProvider {
    private final MontoyaApi api;
    private final CodecEngine engine;

    public CodecRequestEditorProvider(MontoyaApi api, CodecEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
        boolean editable = ctx.editorMode() != EditorMode.READ_ONLY;
        return new CodecRequestEditor(api, engine, editable);
    }
}
