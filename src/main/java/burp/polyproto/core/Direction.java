package burp.polyproto.core;

/** Which side of a message a rule/stage applies to. */
public enum Direction {
    REQUEST, RESPONSE, BOTH;

    /** BOTH covers everything; otherwise must equal the message's concrete direction. */
    public boolean covers(Direction d) { return this == BOTH || this == d; }
}
