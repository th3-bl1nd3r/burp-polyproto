package burp.polyproto.frontier;

import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.protobuf.Protobuf.Field;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * TikTok Frontier WebSocket frame (Sec-WebSocket-Protocol: pbbp2).
 * Mirrors com.bytedance.common.wschannel.model.Frame (Square Wire protobuf), verified via JEB:
 *   1 seqid(u64) 2 logid(u64) 3 service(i32) 4 method(i32) 5 headers[] {1 key,2 value}
 *   6 payload_encoding(str "json"/"pb") 7 payload_type(str) 8 payload(bytes)
 *   9 logidnew(str) 10 server_timing(str) 11 msg_id(str)
 * The envelope does NOT compress the payload; the consuming service decides payload meaning.
 */
public final class Frame {
    public long seqid, logid;
    public int service, method;
    public final List<String[]> headers = new ArrayList<>(); // each = {key, value}
    public String payloadEncoding, payloadType, logidnew, serverTiming, msgId;
    public byte[] payload = new byte[0];

    public static final Map<Integer, String> FIELD_NAMES = new LinkedHashMap<>();
    static {
        FIELD_NAMES.put(1, "seqid");
        FIELD_NAMES.put(2, "logid");
        FIELD_NAMES.put(3, "service");
        FIELD_NAMES.put(4, "method");
        FIELD_NAMES.put(5, "headers");
        FIELD_NAMES.put(6, "payload_encoding");
        FIELD_NAMES.put(7, "payload_type");
        FIELD_NAMES.put(8, "payload");
        FIELD_NAMES.put(9, "logidnew");
        FIELD_NAMES.put(10, "server_timing");
        FIELD_NAMES.put(11, "msg_id");
    }

    public static Frame parse(byte[] b) {
        Frame f = new Frame();
        for (Field x : Protobuf.parse(b)) {
            switch (x.number) {
                case 1: f.seqid = x.varint; break;
                case 2: f.logid = x.varint; break;
                case 3: f.service = (int) x.varint; break;
                case 4: f.method = (int) x.varint; break;
                case 5: {
                    String k = "", v = "";
                    for (Field h : Protobuf.parse(x.data)) {
                        if (h.number == 1 && h.data != null) k = new String(h.data, StandardCharsets.UTF_8);
                        else if (h.number == 2 && h.data != null) v = new String(h.data, StandardCharsets.UTF_8);
                    }
                    f.headers.add(new String[]{ k, v });
                    break;
                }
                case 6: f.payloadEncoding = utf8(x.data); break;
                case 7: f.payloadType = utf8(x.data); break;
                case 8: f.payload = x.data != null ? x.data : new byte[0]; break;
                case 9: f.logidnew = utf8(x.data); break;
                case 10: f.serverTiming = utf8(x.data); break;
                case 11: f.msgId = utf8(x.data); break;
                default: break; // unknown tag, ignore
            }
        }
        return f;
    }

    public byte[] encode() {
        List<Field> fs = new ArrayList<>();
        fs.add(Protobuf.varint(1, seqid));
        fs.add(Protobuf.varint(2, logid));
        fs.add(Protobuf.varint(3, service));
        fs.add(Protobuf.varint(4, method));
        for (String[] h : headers) {
            List<Field> hf = new ArrayList<>();
            hf.add(Protobuf.str(1, h[0] == null ? "" : h[0]));
            hf.add(Protobuf.str(2, h[1] == null ? "" : h[1]));
            fs.add(Protobuf.len(5, Protobuf.encode(hf)));
        }
        if (payloadEncoding != null) fs.add(Protobuf.str(6, payloadEncoding));
        if (payloadType != null) fs.add(Protobuf.str(7, payloadType));
        if (payload != null) fs.add(Protobuf.len(8, payload));
        if (logidnew != null) fs.add(Protobuf.str(9, logidnew));
        if (serverTiming != null) fs.add(Protobuf.str(10, serverTiming));
        if (msgId != null) fs.add(Protobuf.str(11, msgId));
        return Protobuf.encode(fs);
    }

    public String header(String key) {
        for (String[] h : headers) if (h[0].equalsIgnoreCase(key)) return h[1];
        return null;
    }

    public void setHeader(String key, String value) {
        for (String[] h : headers) if (h[0].equalsIgnoreCase(key)) { h[1] = value; return; }
        headers.add(new String[]{ key, value });
    }

    public boolean needsAck() {
        return "1".equals(header("need_ack"));
    }

    public boolean isAck() {
        return "1".equals(header("is_ack"));
    }

    /**
     * Build the ACK frame the client must return when the server frame sets header need_ack=1.
     * Reuses seqid/logid/service/method; sets is_ack=1, ack_id=<server logidnew>, ack_code=0,
     * and echoes x_frontier_msgid. (Verified via JEB: LX/0sIH; ack path.)
     */
    public Frame buildAck() {
        Frame a = new Frame();
        a.seqid = seqid;
        a.logid = logid;
        a.service = service;
        a.method = method;
        a.setHeader("is_ack", "1");
        if (logidnew != null) a.setHeader("ack_id", logidnew);
        a.setHeader("ack_code", "0");
        String mid = header("x_frontier_msgid");
        if (mid != null) a.setHeader("x_frontier_msgid", mid);
        return a;
    }

    private static String utf8(byte[] b) {
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }
}
