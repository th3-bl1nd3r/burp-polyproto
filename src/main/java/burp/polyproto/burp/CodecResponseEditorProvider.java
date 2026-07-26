package burp.polyproto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.polyproto.core.CodecEngine;

public class CodecResponseEditorProvider implements HttpResponseEditorProvider {
    private final MontoyaApi api;
    private final CodecEngine engine;

    public CodecResponseEditorProvider(MontoyaApi api, CodecEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
        return new CodecResponseEditor(api, engine);
    }
}
