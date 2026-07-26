package burp.polyproto.util;

import java.security.MessageDigest;

/** Request-body hashing used by TikTok's TTNet layer. */
public final class Sign {

    /** X-Ss-Stub = uppercase-hex MD5 of the request body (as transmitted). */
    public static String md5UpperHex(byte[] body) {
        try {
            byte[] d = MessageDigest.getInstance("MD5").digest(body);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02X", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private Sign() {}
}
