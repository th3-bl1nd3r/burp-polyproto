package burp.polyproto.burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.polyproto.core.Direction;
import burp.polyproto.core.Msg;
import burp.polyproto.core.Transport;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Adapts a Montoya HTTP request/response into the vendor-neutral {@link Msg} the engine consumes. */
public final class MsgAdapter implements Msg {
    private final Direction direction;
    private final Transport transport;
    private final String host, method, path, contentType, wsSubprotocol;
    private final byte[] body;
    private final List<String> headerNames;
    private final Map<String, String> headers; // lower-case name -> first value

    private MsgAdapter(Direction dir, Transport tr, String host, String method, String path,
                       String ct, String wsProto, byte[] body,
                       List<String> names, Map<String, String> headers) {
        this.direction = dir; this.transport = tr; this.host = host; this.method = method;
        this.path = path; this.contentType = ct; this.wsSubprotocol = wsProto; this.body = body;
        this.headerNames = names; this.headers = headers;
    }

    public static MsgAdapter request(HttpRequest req) {
        Map<String, String> h = new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        for (HttpHeader hh : req.headers()) {
            names.add(hh.name());
            h.putIfAbsent(hh.name().toLowerCase(), hh.value());
        }
        String host = req.httpService() != null ? req.httpService().host() : "";
        return new MsgAdapter(Direction.REQUEST, Transport.HTTP, host, req.method(),
                safePath(req), h.get("content-type"), null, req.body().getBytes(), names, h);
    }

    public static MsgAdapter response(HttpResponse resp, HttpRequest req) {
        Map<String, String> h = new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        for (HttpHeader hh : resp.headers()) {
            names.add(hh.name());
            h.putIfAbsent(hh.name().toLowerCase(), hh.value());
        }
        String host = req != null && req.httpService() != null ? req.httpService().host() : "";
        String path = req != null ? safePath(req) : null;
        String method = req != null ? req.method() : null;
        return new MsgAdapter(Direction.RESPONSE, Transport.HTTP, host, method,
                path, h.get("content-type"), null, resp.body().getBytes(), names, h);
    }

    private static String safePath(HttpRequest req) {
        try { return req.pathWithoutQuery(); } catch (Exception e) { return null; }
    }

    @Override public Direction direction() { return direction; }
    @Override public Transport transport() { return transport; }
    @Override public String host() { return host; }
    @Override public String method() { return method; }
    @Override public String path() { return path; }
    @Override public String header(String name) { return name == null ? null : headers.get(name.toLowerCase()); }
    @Override public boolean hasHeader(String name) { return header(name) != null; }
    @Override public List<String> headerNames() { return headerNames; }
    @Override public String contentType() { return contentType; }
    @Override public String wsSubprotocol() { return wsSubprotocol; }
    @Override public byte[] body() { return body == null ? new byte[0] : body; }
}
