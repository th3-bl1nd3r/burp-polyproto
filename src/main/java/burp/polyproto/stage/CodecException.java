package burp.polyproto.stage;

/** Thrown by a {@link Stage} to abdicate (the engine then falls back to raw/identity). */
public class CodecException extends Exception {
    public CodecException(String message) { super(message); }
    public CodecException(String message, Throwable cause) { super(message, cause); }
}
