package burp.polyproto.core;

import java.util.List;

/**
 * Vendor-neutral, Burp-independent view of one HTTP request/response or WebSocket message.
 * {@code burp.polyproto.burp.MsgAdapter} implements this over Montoya; tests implement it directly.
 * Header lookups are case-insensitive; a missing header returns null.
 */
public interface Msg {
    Direction direction();               // REQUEST or RESPONSE (never BOTH)
    Transport transport();               // HTTP or WEBSOCKET

    String host();                       // may be null/empty
    String method();                     // HTTP method, or null for responses/WS
    String path();                       // path without query, or null

    String header(String name);          // first value, case-insensitive, or null
    boolean hasHeader(String name);
    List<String> headerNames();          // as-sent names, for prefix matching

    String contentType();                // convenience for header("Content-Type")
    String wsSubprotocol();              // Sec-WebSocket-Protocol, or null

    byte[] body();                       // raw wire body bytes (never null; may be empty)
}
