package burp.polyproto.stage.coding;

import io.airlift.compress.lz4.Lz4Compressor;
import io.airlift.compress.lz4.Lz4Decompressor;

import java.util.Arrays;

/**
 * Raw LZ4 <b>block</b> codec (no frame header, no stored size) — the form ByteDance IM uses for
 * large Frontier payloads, signalled by {@code payload_encoding: __lz4}. The uncompressed size is
 * not stored, so {@link #decompress} grows the output buffer until the block fits.
 */
public final class Lz4Codec {

    private static final int MAX_OUT = 64 * 1024 * 1024;

    public static byte[] decompress(byte[] in) {
        if (in == null || in.length == 0) return new byte[0];
        Lz4Decompressor d = new Lz4Decompressor();
        int cap = Math.max(4096, in.length * 8);
        while (true) {
            try {
                byte[] out = new byte[cap];
                int n = d.decompress(in, 0, in.length, out, 0, out.length);
                return Arrays.copyOf(out, n);
            } catch (Exception e) {
                if (cap >= MAX_OUT) throw new RuntimeException("lz4: block did not fit in " + MAX_OUT + " bytes", e);
                cap = Math.min(MAX_OUT, cap * 4);
            }
        }
    }

    public static byte[] compress(byte[] in) {
        Lz4Compressor c = new Lz4Compressor();
        byte[] out = new byte[c.maxCompressedLength(in.length)];
        int n = c.compress(in, 0, in.length, out, 0, out.length);
        return Arrays.copyOf(out, n);
    }

    private Lz4Codec() {}
}
