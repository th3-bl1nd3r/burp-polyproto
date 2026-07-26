package burp.polyproto.util;

import java.io.ByteArrayOutputStream;

/**
 * HTTP/1.1 chunked transfer-encoding de-framer.
 *
 * <p>Some TikTok-Shop / OEC (TokoPro) endpoints answer over HTTP/2 but the front proxy
 * (Server: TLB / Via: google) forwards the origin's HTTP/1.1 <b>chunked</b> body verbatim
 * into the HTTP/2 DATA payload without de-chunking it. Because HTTP/2 carries no
 * {@code Transfer-Encoding: chunked} header, Burp never strips the framing and hands us a
 * body that literally looks like {@code bee\r\n<3054 bytes>\r\n..\r\n0\r\n\r\n}. The chunk-size
 * lines corrupt any downstream gunzip/protobuf parse, so we remove them here.
 *
 * <p>{@link #dechunk} only returns a result when the <i>whole</i> buffer parses as a clean
 * chunk stream; on any inconsistency it returns {@code null} so the caller keeps the original
 * bytes. That makes a false positive on a normal (protobuf/gzip/json) body effectively
 * impossible — those never begin with an ASCII hex-size line.
 */
public final class Chunked {

    /** @return de-chunked bytes if {@code b} is a valid chunked stream, else {@code null}. */
    public static byte[] dechunk(byte[] b) {
        if (b == null || b.length < 3) return null;
        // Must start with an ASCII hex digit — cheap reject for protobuf/gzip/json/text.
        if (hexVal(b[0]) < 0) return null;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int pos = 0;
        boolean sawChunk = false;

        while (pos < b.length) {
            // Read the chunk-size line up to LF.
            int lineStart = pos;
            while (pos < b.length && b[pos] != '\n') pos++;
            if (pos >= b.length) return null;           // no terminator -> not well-formed
            int lineEnd = pos;                          // index of '\n'
            pos++;                                       // consume '\n'
            if (lineEnd > lineStart && b[lineEnd - 1] == '\r') lineEnd--;

            // Strip any chunk extensions (";name=value").
            int hexEnd = lineStart;
            while (hexEnd < lineEnd && b[hexEnd] != ';') hexEnd++;
            if (hexEnd == lineStart) return null;        // empty size

            long size = 0;
            for (int i = lineStart; i < hexEnd; i++) {
                int d = hexVal(b[i]);
                if (d < 0) return null;                  // non-hex -> not chunked
                size = (size << 4) | d;
                if (size > (1L << 31)) return null;      // implausible
            }

            if (size == 0) {                             // terminating chunk
                return sawChunk ? out.toByteArray() : null;
            }

            if (pos + size > b.length) return null;      // truncated / not chunked
            out.write(b, pos, (int) size);
            pos += (int) size;

            // Expect the trailing CRLF (or bare LF) after the chunk data.
            if (pos + 1 < b.length && b[pos] == '\r' && b[pos + 1] == '\n') pos += 2;
            else if (pos < b.length && b[pos] == '\n') pos += 1;
            else if (pos == b.length) { /* data ended exactly at buffer end (truncated capture) */ }
            else return null;                            // junk after chunk -> not chunked

            sawChunk = true;
        }
        // Consumed the whole buffer as valid chunks without an explicit 0-terminator
        // (e.g. a truncated capture): accept only if at least one real chunk was read.
        return sawChunk ? out.toByteArray() : null;
    }

    private static int hexVal(byte c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private Chunked() {}
}
