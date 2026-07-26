package burp.polyproto.stage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The value passed between stages. A stage peels exactly one layer and returns either the
 * inner BYTES (for the next stage), a list of FRAMES (RPC fan-out), or terminal editable TEXT.
 * {@link #meta} carries round-trip parameters the matching encode() needs (key order, variant,
 * stripped guards, dictionary id, ...).
 */
public final class Node {
    public enum Type { BYTES, FRAMES, TEXT }

    public final Type type;
    public byte[] bytes;                  // BYTES
    public List<Frame> frames;            // FRAMES
    public String text;                   // TEXT: terminal editable form
    public String formatId;               // TEXT: which format stage produced it
    public final Map<String, Object> meta = new HashMap<>();

    private Node(Type type) { this.type = type; }

    public static Node bytes(byte[] b) {
        Node n = new Node(Type.BYTES);
        n.bytes = b;
        return n;
    }

    public static Node frames(List<Frame> f) {
        Node n = new Node(Type.FRAMES);
        n.frames = f;
        return n;
    }

    public static Node text(String t, String formatId) {
        Node n = new Node(Type.TEXT);
        n.text = t;
        n.formatId = formatId;
        return n;
    }
}
