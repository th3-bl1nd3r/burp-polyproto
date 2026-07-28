package burp.polyproto.protobuf;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.format.ProtobufStage;
import burp.polyproto.stage.framing.RpcFrameStage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A LEN payload that is a nested message must not be flattened into a string just because its bytes
 * happen to read as printable. Shape taken from a real unary gRPC call whose nested message held two
 * long token-ish strings — 98.6% printable, so the old printable-first test rendered both fields plus
 * their tag/length bytes as one mangled value. Values here are synthetic; no captured traffic.
 */
class ProtoNestingTest {

    /** Same length and alphabet as the tokens that triggered this, but not a real one. */
    private static final String TOKEN =
            "aaaabbbbccccddddeeee.AB-C0DefGhIjKlMnOpQrStUvWxYz0123456789abcd"
          + "EFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzAB";
    private static final String PKG = "com.example.app";

    private static byte[] innerMessage() {
        return Protobuf.encode(List.of(Protobuf.str(1, TOKEN), Protobuf.str(2, PKG)));
    }

    private static byte[] outerMessage() {
        return Protobuf.encode(List.of(Protobuf.len(1, innerMessage())));
    }

    @Test
    void printableNestedMessageIsExpandedNotFlattened() {
        byte[] inner = innerMessage();
        assertTrue(Protobuf.asPrintable(inner) != null,
                "precondition: the nested message reads as printable, which is what caused the bug");
        assertNull(Protobuf.asCleanString(inner),
                "its tag/length bytes are C0 controls, so it is not clean text");
        assertTrue(Protobuf.looksNested(inner));

        assertEquals("1: {\n  1: \"" + TOKEN + "\"\n  2: \"" + PKG + "\"\n}\n",
                ProtoText.encode(outerMessage()));
    }

    @Test
    void treeViewExpandsTheNestedMessage() {
        ProtoNode root = ProtoNodes.parse(outerMessage(), null);
        assertEquals(1, root.children.size());

        ProtoNode outer = root.children.get(0);
        assertEquals(ProtoNode.Kind.MESSAGE, outer.kind);
        assertEquals(2, outer.children.size(), "token and package name must be separate fields");
        assertEquals(TOKEN, outer.children.get(0).value);
        assertEquals(PKG, outer.children.get(1).value);
    }

    @Test
    void schemaRendererExpandsTheNestedMessage() {
        String out = SchemaRenderer.render(outerMessage(), null);
        assertTrue(out.contains("\"" + TOKEN + "\""), out);
        assertTrue(out.contains("\"" + PKG + "\""), out);
        assertFalse(out.contains(TOKEN + PKG), "fields must not be concatenated");
    }

    @Test
    void editableTextRoundTripsByteExact() {
        byte[] outer = outerMessage();
        assertArrayEquals(outer, ProtoText.parse(ProtoText.encode(outer)));
    }

    @Test
    void unaryGrpcFrameUnwrapsToTheMessage() throws Exception {
        byte[] msg = outerMessage();
        ByteArrayOutputStream framed = new ByteArrayOutputStream();
        framed.write(0);                                     // not compressed
        framed.write(new byte[] { 0, 0, (byte) (msg.length >>> 8), (byte) msg.length });
        framed.write(msg);

        RpcFrameStage grpc = new RpcFrameStage();
        PipelineCtx ctx = new PipelineCtx();
        assertTrue(grpc.sniff(framed.toByteArray(), ctx));

        Node n = grpc.decode(framed.toByteArray(), ctx);
        assertArrayEquals(msg, n.bytes);
        assertTrue(ProtobufStage.isProtobuf(n.bytes));
        assertArrayEquals(framed.toByteArray(), grpc.encode(n, ctx));
    }

    // ---- guards against over-correcting: text must stay text ----

    @Test
    void shortTextThatParsesByLuckStaysAString() {
        // "PB" parses cleanly as field 10, varint 66 — but it is a string, not a message.
        assertFalse(Protobuf.looksNested("PB".getBytes(StandardCharsets.UTF_8)));
        assertEquals("1: \"PB\"\n", ProtoText.encode(Protobuf.encode(List.of(Protobuf.str(1, "PB")))));
    }

    @Test
    void ordinaryStringFieldsStayStrings() {
        for (String s : new String[] { PKG, "https://example.com/a/b?c=1", "user@example.com",
                                       "hello world" }) {
            assertFalse(Protobuf.looksNested(s.getBytes(StandardCharsets.UTF_8)), s);
            assertEquals("1: \"" + s + "\"\n",
                    ProtoText.encode(Protobuf.encode(List.of(Protobuf.str(1, s)))), s);
        }
    }

    @Test
    void embeddedJsonStaysAQuotedStringWithEscapes() {
        String json = "{\"k\":\"v\"}";
        assertFalse(Protobuf.looksNested(json.getBytes(StandardCharsets.UTF_8)));

        byte[] msg = Protobuf.encode(List.of(Protobuf.str(1, json)));
        assertEquals("1: \"{\\\"k\\\":\\\"v\\\"}\"\n", ProtoText.encode(msg));
        assertArrayEquals(msg, ProtoText.parse(ProtoText.encode(msg)));
    }

    @Test
    void smallBinaryNestedMessageStillExpands() {
        byte[] inner = Protobuf.encode(List.of(Protobuf.varint(1, 5)));
        assertTrue(Protobuf.looksNested(inner));
        assertEquals("1: {\n  1: 5\n}\n",
                ProtoText.encode(Protobuf.encode(List.of(Protobuf.len(1, inner)))));
    }

    @Test
    void nonCanonicalBytesAreNotTreatedAsAMessage() {
        // field 1, varint 1 written with a redundant continuation byte: parses, but re-encodes
        // shorter — so it was never a message on the wire.
        byte[] nonCanonical = { 0x08, (byte) 0x81, 0x00 };
        assertFalse(Protobuf.looksNested(nonCanonical));
    }

    // ---- control bytes must never sit invisibly in the editable text ----

    @Test
    void controlBytesSurviveTheTextRoundTrip() {
        byte[] msg = Protobuf.encode(List.of(Protobuf.str(1, "ab")));
        String text = ProtoText.encode(msg);
        assertFalse(text.contains(""), "a raw control byte must not reach the editor: " + text);
        assertArrayEquals(msg, ProtoText.parse(text));
    }

    @Test
    void hexEscapeIsAcceptedFromHandEditedText() {
        assertArrayEquals(Protobuf.encode(List.of(Protobuf.str(1, "ab"))),
                ProtoText.parse("1: \"a\\x01b\"\n"));
    }
}
