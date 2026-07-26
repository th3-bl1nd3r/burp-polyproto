package burp.polyproto.stage.format;

import burp.polyproto.core.PipelineCtx;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.CodecException;
import burp.polyproto.stage.Node;
import burp.polyproto.stage.Stage;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/** Terminal XML format: pretty-print for reading; edited text is re-emitted as UTF-8. */
public final class XmlStage implements Stage {
    @Override public String id() { return "xml"; }
    @Override public Kind kind() { return Kind.FORMAT; }

    @Override public boolean sniff(byte[] in, PipelineCtx ctx) {
        return Protobuf.asPrintable(in) != null && looksXml(in);
    }

    @Override public Node decode(byte[] in, PipelineCtx ctx) throws CodecException {
        try {
            Document doc = parseHardened(in);
            String pretty = prettyPrint(doc);
            return Node.text(pretty, "xml");
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("xml pretty-print failed", e);
        }
    }

    @Override public byte[] encode(Node edited, PipelineCtx ctx) {
        return edited.text.getBytes(StandardCharsets.UTF_8);
    }

    @Override public boolean canEncode() { return true; }

    /** Printable body whose trimmed text starts with "<?xml" or a leading <tag ...>. */
    public static boolean looksXml(byte[] b) {
        String s = Protobuf.asPrintable(b);
        if (s == null) return false;
        s = s.trim();
        if (s.length() < 3 || s.charAt(0) != '<') return false;
        if (s.regionMatches(true, 0, "<?xml", 0, 5)) return true;
        // Leading <tag ...>: second char is a name-start char (letter, '_', or ':').
        char c = s.charAt(1);
        return Character.isLetter(c) || c == '_' || c == ':';
    }

    /** Build a DOM with an XXE-hardened factory (no DOCTYPE, no external entities, no XInclude). */
    private static Document parseHardened(byte[] in) throws CodecException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder builder = dbf.newDocumentBuilder();
            InputSource src = new InputSource(new ByteArrayInputStream(in));
            return builder.parse(src);
        } catch (Exception e) {
            throw new CodecException("xml parse failed", e);
        }
    }

    /** Serialize a DOM to an indented string (2-space indent). */
    private static String prettyPrint(Document doc) throws CodecException {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StringWriter out = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(out));
            return out.toString();
        } catch (Exception e) {
            throw new CodecException("xml transform failed", e);
        }
    }
}
