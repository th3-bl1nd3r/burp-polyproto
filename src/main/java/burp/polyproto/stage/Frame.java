package burp.polyproto.stage;

/**
 * One RPC message inside a framed stream (gRPC / gRPC-Web / Connect / event-stream).
 * A data frame carries {@link #payload} (possibly still compressed); a "special" frame is a
 * gRPC-Web trailer or a Connect end-of-stream marker whose ASCII/JSON content is preserved
 * verbatim in {@link #specialText} so encode() can re-append it unchanged.
 */
public final class Frame {
    public int flags;             // bit0=compressed, 0x80=trailer(grpc-web), 0x02=EOS(connect)
    public boolean special;       // true for a trailer / end-of-stream frame
    public String specialText;    // ASCII headers or JSON metadata for a special frame
    public byte[] payload;        // data-frame message bytes (may still be compressed)

    public Frame() {}

    public static Frame data(byte[] payload, int flags) {
        Frame f = new Frame();
        f.payload = payload;
        f.flags = flags;
        return f;
    }

    public static Frame special(String text, int flags) {
        Frame f = new Frame();
        f.special = true;
        f.specialText = text;
        f.flags = flags;
        return f;
    }
}
