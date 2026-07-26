package burp.polyproto.burp;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.polyproto.core.Msg;
import burp.polyproto.rule.HeaderRewrite;
import burp.polyproto.rule.RuleRegistry;

import java.util.List;

/**
 * Applies rule-driven request header rewrites to ALL outgoing traffic — e.g. rewriting
 * {@code Accept-Encoding: ttzip} → {@code gzip} so TikTok returns a body we can decode. Runs on
 * every request, not just the ones with an open editor tab.
 */
public class RuleHttpHandler implements HttpHandler {

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            Msg m = MsgAdapter.request(requestToBeSent);
            List<HeaderRewrite> rewrites = RuleRegistry.get().requestRewrites(m);
            HttpRequest out = requestToBeSent;
            for (HeaderRewrite hr : rewrites) {
                if (hr.name == null) continue;
                String cur = out.headerValue(hr.name);
                if (hr.onlyIfPresent && cur == null) continue;
                if (hr.ifValueContains != null && (cur == null || !cur.contains(hr.ifValueContains))) continue;
                if (hr.remove) {
                    if (out.hasHeader(hr.name)) out = out.withRemovedHeader(hr.name);
                } else if (hr.setValue != null) {
                    out = out.hasHeader(hr.name)
                            ? out.withUpdatedHeader(hr.name, hr.setValue)
                            : out.withAddedHeader(hr.name, hr.setValue);
                }
            }
            return RequestToBeSentAction.continueWith(out);
        } catch (Exception e) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
