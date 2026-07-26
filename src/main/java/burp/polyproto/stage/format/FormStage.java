package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.nio.charset.StandardCharsets;

/** application/x-www-form-urlencoded shown one param per line; re-joined on edit. */
public final class FormStage implements Stage {
    @Override public String id() { return "form"; }
    @Override public Kind kind() { return Kind.FORMAT; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        return Protobuf.asPrintable(in) != null && looksForm(in);
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) {
        String s = new String(in, StandardCharsets.UTF_8);
        return Node.text(s.replace("&", "\n"), "form");
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        return linesToForm(edited.text).getBytes(StandardCharsets.UTF_8);
    }

    @Override public boolean canEncode() { return true; }

    /** Printable body shaped like key=value(&key=value)* (not JSON). */
    public static boolean looksForm(byte[] b) {
        String s = Protobuf.asPrintable(b);
        if (s == null) return false;
        s = s.trim();
        if (s.length() < 3 || s.charAt(0) == '{' || s.charAt(0) == '[') return false;
        if (s.indexOf('=') < 0) return false;
        for (String tok : s.split("&")) {
            if (tok.indexOf('=') < 0) return false;
        }
        return true;
    }

    /** Re-join one-param-per-line back into a&b&c (blank lines ignored). */
    public static String linesToForm(String text) {
        StringBuilder sb = new StringBuilder();
        for (String line : text.split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            if (sb.length() > 0) sb.append('&');
            sb.append(t);
        }
        return sb.toString();
    }
}
