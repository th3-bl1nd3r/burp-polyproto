package burp.polyproto.stage.coding;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * HTTP {@code Content-Encoding: deflate}. In the wild this is EITHER a zlib-wrapped stream
 * (RFC 1950) OR a raw headerless DEFLATE stream (RFC 1951). Only the zlib variant carries a
 * checkable header, so {@link #sniff} may blind-detect zlib but MUST NEVER fire for raw deflate
 * (which has no signature) — raw is only reached via an explicit rule/token. The decoded variant
 * is recorded in {@code node.meta["deflate.raw"]} so {@link #encode} can round-trip faithfully.
 */
public final class DeflateStage implements Stage {
    @Override public String id() { return "deflate"; }
    @Override public Kind kind() { return Kind.CODING; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        if (in == null || in.length < 2) return false;
        // zlib (RFC 1950) header heuristic: CM=8 (DEFLATE), CINFO<=7 (32K window),
        // and the 16-bit CMF|FLG big-endian value is a multiple of 31.
        boolean zlibHeader = (in[0] & 0x0F) == 8
                && ((in[0] >> 4) & 0x0F) <= 7
                && ((((in[0] & 0xff) << 8) | (in[1] & 0xff)) % 31) == 0;
        if (!zlibHeader) return false;
        // Verify the heuristic by actually inflating the whole stream; a false-positive header
        // that does not fully inflate must not be selected. Raw deflate is never sniffed true.
        try {
            inflateAll(in, false);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        byte[] out;
        boolean raw;
        try {
            // Try zlib-wrapped first (Inflater(false), i.e. expects the RFC 1950 header).
            out = inflateAll(in, false);
            raw = false;
        } catch (Exception zlibFail) {
            try {
                // Fall back to raw headerless DEFLATE (Inflater(true) / nowrap).
                out = inflateAll(in, true);
                raw = true;
            } catch (Exception rawFail) {
                throw new CodecException("deflate inflate failed (zlib and raw)", rawFail);
            }
        }
        Node node = Node.bytes(out);
        node.meta.put("deflate.raw", raw);
        return node;
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        Object rawFlag = edited.meta.get("deflate.raw");
        boolean raw = rawFlag instanceof Boolean && (Boolean) rawFlag; // default: zlib-wrapped
        Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION, raw);
        try {
            def.setInput(edited.bytes);
            def.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    Math.max(32, edited.bytes.length / 2));
            byte[] buf = new byte[8192];
            while (!def.finished()) {
                int n = def.deflate(buf);
                if (n > 0) out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            throw new CodecException("deflate failed", e);
        } finally {
            def.end();
        }
    }

    @Override public boolean canEncode() { return true; }

    /** Fully inflate {@code in}; throws on corrupt data, a required dictionary, or truncation. */
    private static byte[] inflateAll(byte[] in, boolean nowrap) throws Exception {
        Inflater inf = new Inflater(nowrap);
        try {
            inf.setInput(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, in.length * 3));
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n > 0) {
                    out.write(buf, 0, n);
                } else {
                    if (inf.finished()) break;
                    // Preset dictionary required, or input exhausted before end-of-stream.
                    if (inf.needsDictionary() || inf.needsInput()) {
                        throw new IOException("incomplete deflate stream");
                    }
                }
            }
            if (!inf.finished()) throw new IOException("deflate stream not finished");
            return out.toByteArray();
        } finally {
            inf.end();
        }
    }
}
