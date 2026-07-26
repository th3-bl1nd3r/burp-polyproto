package burp.polyproto.rule;

/**
 * How to recompute a body-integrity signature after an edit (e.g. TikTok X-Ss-Stub = MD5(body)).
 * {@code enabled=false} (default) leaves the signature STALE — the decisive "is it even checked?" test.
 */
public final class SigSpec {
    public boolean enabled = false;
    public String header;                 // "X-Ss-Stub"
    public String algo;                   // md5-upper-hex | md5-lower-hex | sha256-hex | sha256-b64 | hmac-sha256-b64
    public String over = "wire-body";     // body | wire-body | path+body
    public boolean addIfMissing = true;
}
