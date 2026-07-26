package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

/**
 * Terminal fallback for undecodable bytes: a hex + ASCII dump for reading. The original bytes are
 * kept in the node meta so re-encode is a faithful passthrough (the hex view itself is not edited).
 */
public final class RawStage implements Stage {
    @Override public String id() { return "raw"; }
    @Override public Kind kind() { return Kind.FORMAT; }
    @Override public boolean sniff(byte[] in, PipelineCtx ctx) { return true; }

    @Override public Node decode(byte[] in, PipelineCtx ctx) {
        Node n = Node.text(hexDump(in), "raw");
        n.meta.put("raw.bytes", in);
        return n;
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        Object o = edited.meta.get("raw.bytes");
        return o instanceof byte[] ? (byte[]) o : new byte[0];
    }

    @Override public boolean canEncode() { return true; }

    private static String hexDump(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int off = 0; off < b.length; off += 16) {
            sb.append(String.format("%08x  ", off));
            StringBuilder ascii = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                if (off + i < b.length) {
                    int v = b[off + i] & 0xff;
                    sb.append(String.format("%02x ", v));
                    ascii.append(v >= 0x20 && v < 0x7f ? (char) v : '.');
                } else {
                    sb.append("   ");
                }
                if (i == 7) sb.append(' ');
            }
            sb.append(' ').append(ascii).append('\n');
        }
        return sb.toString();
    }
}
