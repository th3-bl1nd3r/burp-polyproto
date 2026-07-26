package burp.polyproto.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/** gzip helpers. TikTok flags gzip bodies with the NON-standard header X-Bd-Content-Encoding: gzip,
 *  so Burp does not auto-decompress them; we handle it here. (ttzip is separate — see README.) */
public final class Compression {

    public static boolean isGzip(byte[] b) {
        return b != null && b.length > 2 && (b[0] & 0xff) == 0x1f && (b[1] & 0xff) == 0x8b;
    }

    public static byte[] gunzip(byte[] b) throws IOException {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(b));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    public static byte[] gzip(byte[] b) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(out)) {
            g.write(b);
        }
        return out.toByteArray();
    }

    private Compression() {}
}
