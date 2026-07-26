package burp.polyproto.stage.framing;

import java.io.ByteArrayOutputStream;

/** Big-endian uint32 helpers for gRPC / gRPC-Web length prefixes (NOT little-endian like protobuf). */
public final class Be32 {
    public static long readU32(byte[] b, int off) {
        return ((b[off] & 0xffL) << 24) | ((b[off + 1] & 0xffL) << 16)
                | ((b[off + 2] & 0xffL) << 8) | (b[off + 3] & 0xffL);
    }

    public static void writeU32(ByteArrayOutputStream out, long v) {
        out.write((int) ((v >> 24) & 0xff));
        out.write((int) ((v >> 16) & 0xff));
        out.write((int) ((v >> 8) & 0xff));
        out.write((int) (v & 0xff));
    }

    private Be32() {}
}
