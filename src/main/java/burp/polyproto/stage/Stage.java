package burp.polyproto.stage;

import burp.polyproto.core.PipelineCtx;

/**
 * One reversible transform of a single layer (framing, content-coding, or terminal format).
 * The engine composes a chain outer→inner on decode and reverses it on encode.
 *
 * <p>Contract:
 * <ul>
 *   <li>{@link #sniff} is cheap (magic bytes / header / shallow structure) and MUST return
 *       {@code false} for brotli and raw-deflate (no reliable signature) so they are only ever
 *       reached by an explicit rule/header, never blind-detected.</li>
 *   <li>{@link #decode} peels exactly ONE layer, or throws {@link CodecException} to abdicate.</li>
 *   <li>{@link #encode} rebuilds exactly THIS layer from the (possibly edited) node.</li>
 *   <li>If {@link #canEncode} is {@code false} (e.g. brotli, dictionary-zstd) the engine
 *       substitutes an identity fallback on edit and marks the result non-faithful.</li>
 * </ul>
 */
public interface Stage {
    enum Kind { FRAMING, CODING, FORMAT }

    /** Stable token, e.g. "gzip", "grpc", "protobuf", "form+json", "envelope:tiktok.frontier". */
    String id();

    Kind kind();

    /** Cheap structural/magic/header probe. FALSE for brotli & raw-deflate by contract. */
    boolean sniff(byte[] in, PipelineCtx ctx);

    /** Peel one layer. Throw to abdicate (engine falls back to raw/identity). */
    Node decode(byte[] in, PipelineCtx ctx) throws CodecException;

    /** Rebuild this layer from the edited node. */
    byte[] encode(Node edited, PipelineCtx ctx) throws CodecException;

    /** False → this layer cannot be reproduced; engine emits identity and drops the coding header. */
    boolean canEncode();
}
