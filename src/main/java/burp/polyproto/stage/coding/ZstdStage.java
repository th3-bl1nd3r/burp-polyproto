package burp.polyproto.stage.coding;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;
import io.airlift.compress.zstd.ZstdCompressor;
import io.airlift.compress.zstd.ZstdDecompressor;

import java.util.Arrays;

/**
 * Zstandard (RFC 8878) content-coding. Detected by the 4-byte magic 28 B5 2F FD; re-encodable
 * for standard no-dictionary frames. Delegates to the bundled pure-Java aircompressor codec.
 *
 * <p>Frames that require an external dictionary carry no embedded content size and cannot be
 * inflated here; {@link #decode} abdicates on them via {@link CodecException} (expected).
 */
public final class ZstdStage implements Stage {

    /** Upper bound on a single frame's decoded size; guards against absurd/bomb allocations. */
    private static final long MAX_DECOMPRESSED = 1L << 30; // 1 GiB

    @Override public String id() { return "zstd"; }

    @Override public Kind kind() { return Kind.CODING; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        return in != null
                && in.length >= 4
                && (in[0] & 0xff) == 0x28
                && (in[1] & 0xff) == 0xB5
                && (in[2] & 0xff) == 0x2F
                && (in[3] & 0xff) == 0xFD;
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        try {
            ZstdDecompressor d = new ZstdDecompressor();
            long size = ZstdDecompressor.getDecompressedSize(in, 0, in.length);
            if (size <= 0 || size > MAX_DECOMPRESSED) {
                throw new CodecException("zstd: unknown size (dictionary frame?)");
            }
            byte[] out = new byte[(int) size];
            int n = d.decompress(in, 0, in.length, out, 0, out.length);
            return Node.bytes(Arrays.copyOf(out, n));
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("zstd decode failed", e);
        }
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) throws CodecException {
        try {
            ZstdCompressor c = new ZstdCompressor();
            int max = c.maxCompressedLength(edited.bytes.length);
            byte[] out = new byte[max];
            int n = c.compress(edited.bytes, 0, edited.bytes.length, out, 0, max);
            return Arrays.copyOf(out, n);
        } catch (Exception e) {
            throw new CodecException("zstd encode failed", e);
        }
    }

    @Override public boolean canEncode() { return true; }
}