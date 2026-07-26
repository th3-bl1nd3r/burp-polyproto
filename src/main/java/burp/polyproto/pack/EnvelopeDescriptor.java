package burp.polyproto.pack;

/**
 * Field layout of a protobuf WebSocket envelope (generalizes ByteDance Frontier's {@code Frame}).
 * Tags identify where the inner payload, its encoding/type, headers, and routing live, plus the
 * header names used for the ack handshake.
 */
public final class EnvelopeDescriptor {
    public String name = "envelope";
    public int seqidTag = 1, logidTag = 2, serviceTag = 3, methodTag = 4;
    public int headersTag = 5, headerKeyTag = 1, headerValueTag = 2;
    public int payloadEncodingTag = 6, payloadTypeTag = 7, payloadTag = 8;
    public int logidNewTag = 9, serverTimingTag = 10, msgIdTag = 11;

    // ack handshake header names
    public String needAckHeader = "need_ack";
    public String isAckHeader = "is_ack";
    public String ackIdHeader = "ack_id";
    public String ackCodeHeader = "ack_code";
    public String msgIdHeader = "x_frontier_msgid";
}
