package burp.polyproto.frontier;

import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.util.Compression;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Frontier payloads arrive gzipped under {@code payload_encoding: gzip}. They must be peeled for
 * display and restored on edit; showing the compressed bytes as hex hides the whole message.
 * Frame shape is real, values are synthetic — no captured traffic.
 */
class FrameTextTest {

    private static final String PROTO_MARKER = "--- payload (protobuf, editable) ---";
    private static final String HEX_MARKER = "--- payload (hex) ---";

    /** A payload with the shape Frontier carries: a nested message plus repeated records. */
    private static byte[] innerPayload() {
        byte[] session = Protobuf.encode(List.of(
                Protobuf.varint(1, 4),
                Protobuf.str(2, "0"),
                Protobuf.str(3, "1000000000000000001"),
                Protobuf.varint(4, 1700000000000L)));
        byte[] record = Protobuf.encode(List.of(Protobuf.varint(1, 4), Protobuf.varint(3, 1)));
        return Protobuf.encode(List.of(Protobuf.len(1, session), Protobuf.len(2, record)));
    }

    private static Frame gzipFrame(String encoding) throws Exception {
        Frame f = new Frame();
        f.seqid = 5;
        f.service = 20065;
        f.method = 2;
        f.headers.add(new String[] { "X-Cylons", "synthetic-header-value" });
        f.payloadEncoding = encoding;
        f.payloadType = "gzip";
        f.payload = Compression.gzip(innerPayload());
        return f;
    }

    @Test
    void gzipPayloadIsDecompressedAndRenderedAsProtobuf() throws Exception {
        String text = FrameText.toText(gzipFrame("gzip"));

        assertTrue(text.contains("payload_note: decompressed from gzip"), text);
        assertTrue(text.contains(PROTO_MARKER), text);
        assertFalse(text.contains(HEX_MARKER), "a gzip payload must not fall through to hex");
        assertTrue(text.contains("\"1000000000000000001\""), text);
        assertTrue(text.contains("service: 20065"), text);
    }

    @Test
    void editedGzipFrameGoesBackOutCompressed() throws Exception {
        Frame out = FrameText.parse(FrameText.toText(gzipFrame("gzip")));

        assertTrue(Compression.isGzip(out.payload), "payload must be re-gzipped for the wire");
        assertArrayEquals(innerPayload(), Compression.gunzip(out.payload));
        assertEquals(20065, out.service);
        assertEquals(5, out.seqid);
        assertEquals("X-Cylons", out.headers.get(0)[0]);
    }

    @Test
    void gzipIsDetectedByMagicEvenWhenTheHeaderDoesNotSaySo() throws Exception {
        // payload_encoding claims "pb" but the bytes are gzip: the note carries the round-trip.
        Frame out = FrameText.parse(FrameText.toText(gzipFrame("pb")));

        assertTrue(Compression.isGzip(out.payload));
        assertArrayEquals(innerPayload(), Compression.gunzip(out.payload));
    }

    @Test
    void editsToADecompressedPayloadSurviveTheRoundTrip() throws Exception {
        String text = FrameText.toText(gzipFrame("gzip"));
        String edited = text.replace("\"1000000000000000001\"", "\"1234567890123456789\"");

        byte[] payload = Compression.gunzip(FrameText.parse(edited).payload);
        assertTrue(new String(payload, StandardCharsets.UTF_8).contains("1234567890123456789"));
    }

    @Test
    void uncompressedProtobufPayloadIsUntouched() {
        Frame f = new Frame();
        f.payloadEncoding = "pb";
        f.payload = innerPayload();

        String text = FrameText.toText(f);
        assertFalse(text.contains("payload_note"), text);
        assertArrayEquals(innerPayload(), FrameText.parse(text).payload);
    }

    @Test
    void zstdDictPayloadIsStillShownAsHexAndNotRecompressed() {
        Frame f = new Frame();
        f.headers.add(new String[] { "compress_type", "zstd" });
        f.payloadEncoding = "gzip"; // header wins: we cannot decode without the runtime dictionary
        f.payload = new byte[] { 0x28, (byte) 0xb5, 0x2f, (byte) 0xfd, 0x01, 0x02, 0x03 };

        String text = FrameText.toText(f);
        assertTrue(text.contains("cannot decode without the runtime dictionary"), text);
        assertTrue(text.contains(HEX_MARKER), text);
        assertArrayEquals(f.payload, FrameText.parse(text).payload, "hex is already the wire form");
    }

    @Test
    void corruptGzipFallsBackToHexWithoutLosingBytes() {
        Frame f = new Frame();
        f.payloadEncoding = "gzip";
        f.payload = new byte[] { 0x1f, (byte) 0x8b, 0x08, 0x00, 0x63, 0x72, 0x75, 0x64 };

        String text = FrameText.toText(f);
        assertTrue(text.contains("could not decompress"), text);
        assertTrue(text.contains(HEX_MARKER), text);
        assertArrayEquals(f.payload, FrameText.parse(text).payload);
    }
}
