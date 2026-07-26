package burp.polyproto.rule;

import burp.polyproto.core.Direction;

/** A conditional request/response header rewrite (e.g. force Accept-Encoding: gzip to defeat ttzip). */
public final class HeaderRewrite {
    public String name;
    public String setValue;
    public boolean onlyIfPresent = false;
    public String ifValueContains;   // apply only if the current value contains this (null = always)
    public boolean remove = false;
    public Direction applyTo = Direction.REQUEST;
}
