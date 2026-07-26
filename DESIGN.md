# Vendor-Neutral Codec Engine for Burp — Authoritative Design

*Synthesis of the "minimal-refactor", "pipeline-first (Composer)", and "rule-first (Rulex)" candidates. The winning shape: **one JSON ruleset is the source of truth**, interpreted by a **pipeline of composable `Stage`s**, reusing the **entire proven `burp.tt.*` generic core verbatim**. Auto-detect is itself the lowest-priority rule. TikTok and Meta ship as bundled packs, fully subsuming both current tools.*

---

## 1. Overview + Module Map

The extension is a thin interpreter over a single `Ruleset` JSON document. Per message it (a) resolves the highest-priority matching `Rule`, (b) compiles that rule's `forcePipeline` token list — or `["auto"]`, which delegates to the `Detector` — into an ordered, reversible chain of `Stage`s spanning **framing → coding → format**, (c) decodes to editable text while recording a `DecodeTrace`, and (d) on edit reverses the trace exactly, recomputing signatures/lengths last. Rules never contain decode logic; they only *select, override, annotate*. The security-sensitive parsing lives in one audited set of `Stage`s. TikTok/Meta vendor behavior is **data** (rules + schema packs + a WS-envelope descriptor), not code.

### Root package: `burp.codec`

```
burp.codec
├── core           CodecEngine, Msg, Direction, Transport, DecodeResult, DecodeTrace,
│                  Pipeline, PipelineCompiler, PipelineCtx, Detector
├── stage          Stage (SPI), Kind, Node, StageRegistry, StageMeta, CodecException
│   ├── framing    ChunkedStage, RpcFrameStage, GrpcWebTextStage, ConnectStreamStage,
│   │              EventStreamStage, EnvelopeStage, Be32
│   ├── coding     GzipStage, DeflateStage, ZstdStage, BrotliStage, Lz4Stage,
│   │              SnappyStage, IdentityStage, EncodingHeaderResolver, OptionalCodec
│   └── format     JsonStage, ProtobufStage, FormStage, FormJsonStage, XmlStage,
│                  MsgPackStage, CborStage, TextStage, RawStage
├── rule           Rule, Match, HeaderMatch, Action, HeaderRewrite, SigSpec, LabelSpec,
│                  Ruleset, RuleCodec, RuleRegistry
├── pack           Pack (SPI), PackRegistry, SchemaPackStore, SchemaPackDef,
│                  EnvelopeDescriptor, LabelExtractor
│   ├── tiktok     TikTokPack   (rules + tiktok.im schema + tiktok.frontier envelope)
│   └── meta       MetaPack     (rules + meta.graphql label extractor)
├── util           Json (NEW, dep-free parse/emit), Deflate (NEW, zlib/raw)
├── ui             RulesTab, RuleTableModel, RuleDialog, DecoderPanel, Breadcrumb
└── burp           CodecExtension, MsgAdapter, RuleHttpHandler,
                   CodecRequestEditor, CodecResponseEditor, CodecWebSocketEditor, providers
```

### Disposition of existing `burp.tt.*` classes

| Existing class | Disposition | Destination / note |
|---|---|---|
| `burp.tt.protobuf.Protobuf` | **REUSE verbatim** | `burp.codec` depends on `parse/encode/asPrintable/varint/str/len` |
| `burp.tt.protobuf.ProtoText` | **REUSE verbatim** | lossless protobuf edit text |
| `burp.tt.protobuf.SchemaRenderer` | **REUSE verbatim** | protobuf name-overlay render |
| `burp.tt.protobuf.ProtoSchema` | **REUSE verbatim** | field-name overlay tree |
| `burp.tt.util.Compression` | **REUSE verbatim** | `GzipStage` delegates here |
| `burp.tt.util.Chunked` | **REUSE verbatim** | `ChunkedStage` delegates here |
| `burp.tt.util.Sign` | **REUSE** (+`hmacSha256`) | `md5UpperHex` for `SigSpec`; add HMAC helper |
| `burp.tt.util.JsonPretty` | **REUSE verbatim** | display + `RuleCodec` writer |
| `burp.tt.ui.CodeView` | **REUSE verbatim** | editor pane |
| `burp.tt.util.Hosts` | **DEMOTE to data** | `isTikTok` host list → `hostsAny` in TikTok rules; class deletable |
| `burp.tt.im.ImSchema` | **MOVE → `pack.tiktok`** | rebuilt as `tiktok.im` `SchemaPackDef`; `isImPath` → rule `pathRegex` |
| `burp.tt.frontier.Frame` / `FrameText` | **MOVE → `pack.tiktok`** | generalized by descriptor-driven `EnvelopeStage`; `FrameText` becomes terminal editable text |
| `burp.tt.http.AcceptEncodingHandler` | **DELETE → data** | becomes a `rewriteHeader` rule executed by `RuleHttpHandler` |
| `burp.tt.TtCodec` | **MODIFY → helpers** | static `looksForm/looksJson/linesToForm` consumed by format stages; pipeline methods retired |
| `burp.tt.Config`, `TtHttpRequest/ResponseEditor(+providers)`, `TtWebSocketEditor(+provider)`, `TtDecoderExtension`, `ui.ControlTab` | **REPLACE** | rule-driven equivalents in `burp.codec.burp` / `burp.codec.ui` |
| MetaAPIDecoder (Extension B, all Gson/Extender code) | **REPLACE → `pack.meta` + `FormJsonStage`** | Gson dropped for `util.Json`; shadowJar collapses |

---

## 2. Core Java Interfaces (actual signatures)

### 2.1 The `Stage` SPI + `Node`

```java
package burp.codec.stage;

public interface Stage {
    String  id();                                  // "gzip","grpc","protobuf","form+json","envelope:tiktok.frontier"
    Kind    kind();                                // FRAMING | CODING | FORMAT
    boolean sniff(byte[] in, PipelineCtx ctx);     // cheap; magic/header/structural. FALSE for br & raw-deflate.
    Node    decode(byte[] in, PipelineCtx ctx) throws CodecException;  // peel ONE layer; throw to abdicate
    byte[]  encode(Node edited, PipelineCtx ctx) throws CodecException;// rebuild THIS layer
    boolean canEncode();                           // false => engine substitutes identity fallback on edit

    enum Kind { FRAMING, CODING, FORMAT }
}

public final class Node {
    public enum Type { BYTES, FRAMES, TEXT }
    public final Type type;
    public byte[] bytes;                            // BYTES: buffer for next inner stage
    public java.util.List<Frame> frames;           // FRAMES: gRPC / gRPC-web / connect / eventstream fan-out
    public String text, formatId;                  // TEXT: terminal editable form
    public final java.util.Map<String,Object> meta = new java.util.HashMap<>(); // round-trip params

    public static Node bytes(byte[] b);
    public static Node frames(java.util.List<Frame> f);
    public static Node text(String t, String formatId);
}

public final class Frame {                         // one RPC message
    public int flags;                              // bit0=compressed, 0x80=trailer(grpc-web), 0x02=EOS(connect)
    public boolean special;                        // trailer / end-of-stream marker
    public String specialText;                     // ASCII headers or JSON metadata for special frames
    public byte[] payload;                         // data-frame message bytes (still possibly compressed)
    public Pipeline child;                         // sub-decode of a data frame's payload
}
```

`CodecException extends Exception`. `StageMeta` is a typed `{stageId, Map<String,Object> params}` recorded per peel step.

### 2.2 `StageRegistry` — the single extensibility seam

```java
package burp.codec.stage;

public final class StageRegistry {
    public void    register(String token, java.util.function.Supplier<Stage> factory);
    public Stage   resolve(String token, PipelineCtx ctx);   // "gzip", "envelope:<pack>", "zstd-dict:<name>"
    public Stage   firstMatching(java.util.EnumSet<Stage.Kind> kinds, byte[] buf, PipelineCtx ctx); // priority order
    public boolean isKnown(String token);                    // used by RuleCodec.validate
    public java.util.Set<String> tokens();
    public int     priority(String token);                   // detect precedence
}
```

Detect precedence (priority-ordered, magic-first): FRAMING `grpc-web-text > grpc-web > grpc > connect-stream > eventstream > chunked > envelope`; CODING `zstd > gzip > lz4-frame > snappy-framed > zlib > (header-gated) br > (trial) raw-deflate`; FORMAT resolved by `Detector` (see §4).

### 2.3 `Detector`

```java
package burp.codec.core;

public final class Detector {
    public Detector(StageRegistry reg);
    public java.util.List<String> sniff(byte[] wire, Msg msg);   // full token list e.g. ["dechunk","gzip","protobuf"]
    public String       sniffFraming(byte[] wire, Msg msg);      // "grpc"|"grpc-web"|"grpc-web-text"|"chunked"|null
    public java.util.List<String> sniffCodings(byte[] inner, Msg msg, EncodingHeaderResolver enc); // reverse-order peel
    public String       sniffFormat(byte[] plain, Msg msg);      // text: json>xml>form+json>form>text
                                                                 // bin:  cbor-magic>protobuf>msgpack>cbor>raw
    public boolean      looksDecodable(byte[] wire, Msg msg);    // gate for isEnabledFor when no rule matches
}
```

### 2.4 Rule model + `RuleRegistry`

```java
package burp.codec.rule;

public final class Rule {
    public String id, name;
    public boolean enabled = true;
    public int priority = 100;                     // HIGHER wins; ties by document order; catch-all "auto" = 0
    public Direction direction = Direction.BOTH;
    public Match  match  = new Match();
    public Action action = new Action();
    public boolean matches(Msg m);                 // direction.covers(m.direction()) && match.matches(m)
}

public final class Match {
    public Transport transport;                    // HTTP | WEBSOCKET | null(any)
    public java.util.List<String> hostsAny;        // ci substring, any-of
    public String pathRegex;                       // Java regex on pathWithoutQuery
    public java.util.List<String> methods;         // null/empty = any
    public java.util.List<String> contentTypesAny; // ci substring, any-of
    public String wsSubprotocol;                   // Sec-WebSocket-Protocol equals, e.g. "pbbp2"
    public java.util.List<String> headerNamePrefixAny; // "x-fb-","x-graphql-"
    public java.util.List<HeaderMatch> headers;    // ALL must match (AND)
    public java.util.List<Match> anyOf;            // OR-group of nested matches
    transient java.util.regex.Pattern pathRe;
    public boolean matches(Msg m);
}

public final class HeaderMatch { public String name; public String valueRegex; /*null=presence*/ }

public final class Action {
    public java.util.List<String> forcePipeline;   // null or ["auto"] => Detector
    public java.util.List<String> encodingHeaders; // proprietary CE aliases, e.g. "X-Bd-Content-Encoding"
    public String perMessageCodecHeader;           // "grpc-encoding" / "Connect-Content-Encoding"
    public String schemaPack;                      // named ProtoSchema overlay / envelope descriptor
    public String schemaSelect;                    // "byDirection:REQUEST=Request,RESPONSE=Response"
    public java.util.List<HeaderRewrite> rewriteHeader;
    public SigSpec recomputeSig;
    public LabelSpec label;
}

public final class HeaderRewrite {
    public String name, setValue, ifValueContains;
    public boolean onlyIfPresent = false, remove = false;
    public Direction applyTo = Direction.REQUEST;
}

public final class SigSpec {
    public boolean enabled = false;                // default FALSE = leave signature STALE (the tamper test)
    public String  header;                         // "X-Ss-Stub"
    public String  algo;                           // md5-upper-hex|md5-lower-hex|sha256-hex|sha256-b64|hmac-sha256-b64
    public String  over = "wire-body";             // body | wire-body | path+body
    public boolean addIfMissing = true;
}

public final class LabelSpec {
    public String from;                            // form-json-field|path-regex|header|proto-field|envelope-field
    public String key, pattern, template;          // template e.g. "{value} (doc_id={doc_id})"
    public java.util.List<String> alsoExtract;
}

public enum Direction { REQUEST, RESPONSE, BOTH; public boolean covers(Direction d){return this==BOTH||this==d;} }
public enum Transport { HTTP, WEBSOCKET }
```

```java
public final class RuleRegistry {
    private static final RuleRegistry I = new RuleRegistry();
    public static RuleRegistry get(){ return I; }
    private volatile java.util.List<Rule> rules = java.util.List.of();   // immutable snapshot, lock-free
    public void set(java.util.List<Rule> rs);          // this.rules = List.copyOf(sortByPriorityDesc(rs))
    public java.util.List<Rule> snapshot();
    public Rule firstMatch(Msg m);                     // first enabled rule whose matches(m)
    public java.util.List<HeaderRewrite> requestRewrites(Msg m); // union across ALL matching enabled rules
}

public final class RuleCodec {
    public static Ruleset fromJson(String json) throws CodecException;    // strict: reject unknown stage tokens
    public static String  toJson(Ruleset rs);                            // via JsonPretty (stable diffs)
    public static java.util.List<String> validate(Ruleset rs, StageRegistry reg);
}
public final class Ruleset {
    public int version;
    public java.util.List<Rule> rules;
    public java.util.Map<String,SchemaPackDef> schemaPacks;
    public java.util.Map<String,String> dictionaries;   // name -> base64 zstd dict
}
```

### 2.5 SchemaPack registry + Pack SPI

```java
package burp.codec.pack;

public final class SchemaPackStore {
    public void        load(java.util.Map<String,SchemaPackDef> defs, java.util.Map<String,String> dicts);
    public ProtoSchema protoSchema(String pack, Direction dir);     // overlay for SchemaRenderer
    public EnvelopeDescriptor envelope(String pack);                // non-null for kind:"envelope"
    public byte[]      dictionary(String name);                     // decoded zstd dict, or null
}

public final class SchemaPackDef {
    public String kind;                                             // "protobuf" | "envelope"
    public java.util.Map<String,String> select;                    // protobuf: direction -> root message name
    public java.util.Map<String, java.util.Map<String,Object>> messages; // msgName -> {tag: name | {name,msg:<ref>}}
    public java.util.Map<String,Object> envelope;                  // envelope descriptor (field-tag map + ack)
}

public final class EnvelopeDescriptor {                            // generalizes frontier.Frame
    public int payloadField, encodingField, headersField, serviceField, methodField;
    public int headerKeyTag, headerValueTag;
    public java.util.Map<Integer,String> fieldNames;
    public java.util.Map<String,String> ack;                       // need_ack/is_ack/ack_id/ack_code/x_frontier_msgid
}

public interface LabelExtractor { String label(DecodeResult decoded, Msg ctx); }

/** The SPI a vendor pack implements to contribute rules + schemas + a WS codec. */
public interface Pack {
    String id();                                                   // "tiktok" | "meta"
    java.util.List<Rule> rules();                                  // bundled default rules
    void registerSchemas(SchemaPackStore packs);                   // protobuf overlays + envelope descriptors
    void registerStages(StageRegistry stages);                     // optional custom Stage(s), e.g. an envelope codec
    LabelExtractor labelExtractor(String name);                    // or null
}

public final class PackRegistry {
    public void       register(Pack p);
    public ProtoSchema schema(String packId, String path, Direction d);
    public byte[]     dict(String packId);
    public java.util.List<Rule> allBuiltinRules();                 // BuiltinRules seed = concat of pack.rules() + generic
}
```

### 2.6 Engine + Pipeline

```java
package burp.codec.core;

public final class CodecEngine {
    public CodecEngine(StageRegistry stages, RuleRegistry rules, SchemaPackStore packs, Detector detector, Logger log);
    public DecodeResult decode(Msg msg);                                  // rule -> compile -> decode; RAW on failure
    public byte[]       encode(DecodeResult prior, String editedText) throws CodecException; // reverse recorded trace
    public boolean      isDecodable(Msg msg);                             // gates isEnabledFor
}

public final class DecodeResult {
    public Pipeline pipeline; public DecodeTrace trace;
    public String text;                     // editable terminal text
    public String breadcrumb;               // "chunked › gzip › protobuf (tiktok.im/Request)"
    public String label;                    // may be null
    public boolean faithfulReencode;        // false => identity fallback on edit
    public String note;                     // "brotli not reproducible; will resend identity"
    public Rule matchedRule;
    public boolean editable;                // EditorMode != READ_ONLY && format != RAW
}

public final class Pipeline {
    public java.util.List<String> tokens;
    public DecodeTrace decode(byte[] wire, PipelineCtx ctx) throws CodecException;
    public byte[]      encode(String editedText, DecodeTrace trace, PipelineCtx ctx) throws CodecException;
    public java.util.List<String> breadcrumb();
}
public final class PipelineCompiler { public Pipeline compile(java.util.List<String> tokens, PipelineCtx ctx); }
public final class DecodeTrace { public java.util.List<StageMeta> steps; public String terminalFormat; public String plaintext; public boolean faithful; }
```

---

## 3. Rule JSON Schema + Complete Example Ruleset

### 3.1 Schema (draft-2020-12, abridged to the load-bearing shape)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Codec Ruleset",
  "type": "object",
  "required": ["version", "rules"],
  "properties": {
    "version": { "const": 1 },
    "rules": { "type": "array", "items": { "$ref": "#/$defs/rule" } },
    "schemaPacks": { "type": "object", "additionalProperties": { "$ref": "#/$defs/pack" } },
    "dictionaries": { "type": "object", "additionalProperties": { "type": "string" } }
  },
  "$defs": {
    "rule": {
      "type": "object", "required": ["id","match","action"],
      "properties": {
        "id": {"type":"string"}, "name": {"type":"string"},
        "enabled": {"type":"boolean","default":true},
        "priority": {"type":"integer","default":100,"description":"higher wins; ties=document order; auto=0"},
        "direction": {"enum":["REQUEST","RESPONSE","BOTH"],"default":"BOTH"},
        "match": {"$ref":"#/$defs/match"}, "action": {"$ref":"#/$defs/action"}
      }
    },
    "match": {
      "type":"object","description":"top-level fields AND-ed; anyOf is an OR-group; {} matches all",
      "properties": {
        "transport": {"enum":["HTTP","WEBSOCKET"]},
        "hostsAny": {"type":"array","items":{"type":"string"}},
        "pathRegex": {"type":"string"},
        "methods": {"type":"array","items":{"type":"string"}},
        "contentTypesAny": {"type":"array","items":{"type":"string"}},
        "wsSubprotocol": {"type":"string"},
        "headerNamePrefixAny": {"type":"array","items":{"type":"string"}},
        "headers": {"type":"array","items":{"$ref":"#/$defs/headerMatch"}},
        "anyOf": {"type":"array","items":{"$ref":"#/$defs/match"}}
      }
    },
    "headerMatch": {"type":"object","required":["name"],
      "properties":{"name":{"type":"string"},"valueRegex":{"type":"string"}}},
    "action": {
      "type":"object",
      "properties": {
        "forcePipeline": {"type":"array","items":{"type":"string"},
          "description":"ordered outer->inner tokens; omit or [\"auto\"] to sniff. FRAMING {dechunk,grpc,grpc-web,grpc-web-text,connect-stream,eventstream,envelope:<pack>}; CODING {gzip,zlib,deflate-raw,br,zstd,zstd-dict:<name>,lz4,snappy,identity}; FORMAT {json,protobuf,form,form+json,xml,msgpack,cbor,text,raw}; META {auto,auto-format}. Suffix '?' = apply only if sniff() matches else skip."},
        "encodingHeaders": {"type":"array","items":{"type":"string"}},
        "perMessageCodecHeader": {"type":"string"},
        "schemaPack": {"type":"string"},
        "schemaSelect": {"type":"string"},
        "rewriteHeader": {"type":"array","items":{"$ref":"#/$defs/headerRewrite"}},
        "recomputeSig": {"$ref":"#/$defs/sig"},
        "label": {"$ref":"#/$defs/label"}
      }
    },
    "headerRewrite": {"type":"object","required":["name"],
      "properties":{"name":{"type":"string"},"setValue":{"type":"string"},
        "onlyIfPresent":{"type":"boolean","default":false},"ifValueContains":{"type":"string"},
        "remove":{"type":"boolean","default":false},"applyTo":{"enum":["REQUEST","RESPONSE"],"default":"REQUEST"}}},
    "sig": {"type":"object","required":["header","algo"],
      "properties":{"enabled":{"type":"boolean","default":false},"header":{"type":"string"},
        "algo":{"enum":["md5-upper-hex","md5-lower-hex","sha256-hex","sha256-b64","hmac-sha256-b64"]},
        "over":{"enum":["body","wire-body","path+body"],"default":"wire-body"},
        "addIfMissing":{"type":"boolean","default":true}}},
    "label": {"type":"object","required":["from"],
      "properties":{"from":{"enum":["form-json-field","path-regex","header","proto-field","envelope-field"]},
        "key":{"type":"string"},"pattern":{"type":"string"},"template":{"type":"string"},
        "alsoExtract":{"type":"array","items":{"type":"string"}}}},
    "pack": {"type":"object","required":["kind"],
      "properties":{"kind":{"enum":["protobuf","envelope"]},
        "select":{"type":"object","additionalProperties":{"type":"string"}},
        "messages":{"type":"object"},"envelope":{"type":"object"}}}
  }
}
```

### 3.2 Complete built-in ruleset (reproduces every TikTok + Meta behavior + generic gRPC + auto)

```json
{
  "version": 1,
  "rules": [
    {
      "id": "tiktok.accept-encoding", "name": "TikTok: defeat ttzip (force Accept-Encoding: gzip)",
      "enabled": true, "priority": 900, "direction": "REQUEST",
      "match": { "hostsAny": ["tiktok","tiktokv","byteoversea","bytedance","musical.ly","ibyteimg","tiktokcdn"],
                 "headers": [{ "name": "Accept-Encoding", "valueRegex": "ttzip" }] },
      "action": { "rewriteHeader": [
        { "name": "Accept-Encoding", "setValue": "gzip", "onlyIfPresent": true, "ifValueContains": "ttzip" } ] }
    },
    {
      "id": "tiktok.x-ec", "name": "TikTok: request protobuf responses (X-Ec-Response-Format)",
      "enabled": false, "priority": 850, "direction": "REQUEST",
      "match": { "hostsAny": ["tiktok","byteoversea"], "pathRegex": "/(api|aweme|oec)/" },
      "action": { "rewriteHeader": [{ "name": "X-Ec-Response-Format", "setValue": "protobuf" }] }
    },
    {
      "id": "tiktok.frontier", "name": "TikTok Frontier WebSocket (pbbp2 protobuf envelope)",
      "enabled": true, "priority": 800, "direction": "BOTH",
      "match": { "transport": "WEBSOCKET", "hostsAny": ["frontier","tiktok","byteoversea"], "wsSubprotocol": "pbbp2" },
      "action": { "forcePipeline": ["envelope:tiktok.frontier","gzip?","auto-format"],
                  "schemaPack": "tiktok.frontier",
                  "label": { "from": "envelope-field", "key": "method",
                             "template": "Frontier svc={service} method={method} {ackFlags}" } }
    },
    {
      "id": "tiktok.im", "name": "TikTok IM (Request/Response protobuf, hidden gzip, stub)",
      "enabled": true, "priority": 700, "direction": "BOTH",
      "match": { "hostsAny": ["tiktok","byteoversea","bytedance"],
                 "pathRegex": "/(v[123])/(message|conversation)/|/(message|conversation)/get" },
      "action": { "forcePipeline": ["dechunk?","gzip?","protobuf"],
                  "encodingHeaders": ["X-Bd-Content-Encoding"],
                  "schemaPack": "tiktok.im",
                  "schemaSelect": "byDirection:REQUEST=Request,RESPONSE=Response",
                  "recomputeSig": { "enabled": false, "header": "X-Ss-Stub", "algo": "md5-upper-hex", "over": "wire-body" },
                  "label": { "from": "path-regex", "pattern": "/(v[123])/(message|conversation)/([^/?]+)", "template": "IM {2}/{3}" } }
    },
    {
      "id": "tiktok.generic", "name": "TikTok generic body (auto + X-Bd hidden gzip + stale stub)",
      "enabled": true, "priority": 100, "direction": "BOTH",
      "match": { "hostsAny": ["tiktok","tiktokv","byteoversea","bytedance","musical.ly","ibyteimg"] },
      "action": { "forcePipeline": ["dechunk?","gzip?","auto-format"],
                  "encodingHeaders": ["X-Bd-Content-Encoding"],
                  "recomputeSig": { "enabled": false, "header": "X-Ss-Stub", "algo": "md5-upper-hex", "over": "wire-body" } }
    },
    {
      "id": "meta.graphql", "name": "Meta / Facebook / Instagram GraphQL (form + embedded JSON)",
      "enabled": true, "priority": 700, "direction": "REQUEST",
      "match": { "methods": ["POST"],
                 "anyOf": [
                   { "hostsAny": ["facebook.com","instagram.com","graph.facebook.com","fbcdn.net","meta.com"] },
                   { "headers": [{ "name": "x-fb-friendly-name" }, { "name": "fb-friendly-name" }] },
                   { "headerNamePrefixAny": ["x-fb-","x-graphql-","x-ig-"] } ] },
      "action": { "forcePipeline": ["gzip?","zstd?","form+json"],
                  "label": { "from": "form-json-field", "key": "fb_api_req_friendly_name", "template": "{value}",
                             "alsoExtract": ["doc_id","client_doc_id","av","__user"] } }
    },
    {
      "id": "grpc.generic", "name": "Generic gRPC (5-byte framing, per-message codec)",
      "enabled": true, "priority": 300, "direction": "BOTH",
      "match": { "contentTypesAny": ["application/grpc"] },
      "action": { "forcePipeline": ["grpc","protobuf"], "perMessageCodecHeader": "grpc-encoding",
                  "rewriteHeader": [{ "name": "grpc-accept-encoding", "setValue": "identity", "onlyIfPresent": true }],
                  "label": { "from": "path-regex", "pattern": "/([^/]+)/([^/?]+)$", "template": "{1}/{2}" } }
    },
    {
      "id": "grpc.web", "name": "Generic gRPC-Web (+text base64, trailer frame)",
      "enabled": true, "priority": 300, "direction": "BOTH",
      "match": { "contentTypesAny": ["application/grpc-web"] },
      "action": { "forcePipeline": ["grpc-web","protobuf"], "perMessageCodecHeader": "grpc-encoding" }
    },
    {
      "id": "auto", "name": "Auto-detect (catch-all)",
      "enabled": true, "priority": 0, "direction": "BOTH",
      "match": {}, "action": { "forcePipeline": ["auto"] }
    }
  ],
  "schemaPacks": {
    "tiktok.im": {
      "kind": "protobuf",
      "select": { "REQUEST": "Request", "RESPONSE": "Response" },
      "messages": {
        "Request":  { "1":"cmd","2":"sequence_id","3":"sdk_version","4":"token","6":"inbox_type",
                      "8":{"name":"body","msg":"RequestBody"}, "15":"headers", "17":"token_info" },
        "Response": { "1":"cmd","2":"sequence_id","3":"sdk_version",
                      "8":{"name":"body","msg":"ResponseBody"}, "15":"headers" },
        "RequestBody": { "2200":{"name":"get_messages_body","msg":"GetMessagesRequestBody"} },
        "ResponseBody": { "2200":{"name":"get_messages_body","msg":"GetMessagesResponseBody"} },
        "GetMessagesRequestBody": { "1":"conversation_id","2":"conversation_type","3":"conversation_short_id" },
        "GetMessagesResponseBody": { "1":{"name":"messages","msg":"MessageBody"}, "2":"errors" },
        "MessageBody": { "1":"conversation_id","3":"server_message_id","6":"message_type","8":"content","10":"create_time" }
      }
    },
    "tiktok.frontier": {
      "kind": "envelope",
      "envelope": {
        "seqid":1,"logid":2,"service":3,"method":4,
        "headers":{"tag":5,"keyTag":1,"valueTag":2},
        "payloadEncoding":6,"payloadType":7,"payload":8,"logidnew":9,"serverTiming":10,"msgId":11,
        "ack":{ "needAckHeader":"need_ack","isAckHeader":"is_ack","ackIdHeader":"ack_id",
                "ackCodeHeader":"ack_code","msgIdHeader":"x_frontier_msgid" }
      }
    }
  },
  "dictionaries": {}
}
```

*(The full `tiktok.im` `messages` map ports `ImSchema` verbatim — abbreviated above.)*

---

## 4. Decode Pipeline (auto-detect) + Encode Pipeline (edit)

### DECODE — `CodecEngine.decode(msg)`

**STEP 0 · RESOLVE (rule-first).** `MsgAdapter` wraps the Burp message as `Msg`. `rule = RuleRegistry.firstMatch(msg)`. `tokens = rule.action.forcePipeline`; if null/`["auto"]`, `tokens = Detector.sniff(wire,msg)`. The catch-all `auto` rule (priority 0, `match:{}`) guarantees a match. **Auto-detect is not a separate path — it is the pipeline the lowest rule names.** `encodingHeaders`, `perMessageCodecHeader`, `schemaPack`, `schemaSelect` are attached to `PipelineCtx`.

**STEP 1 · COMPILE.** `PipelineCompiler` walks tokens outer→inner via `StageRegistry`. Meta-tokens: a `?`-suffixed token is kept only if `Stage.sniff()` fires on the current buffer (else dropped = identity); `auto`/`auto-format` is expanded in place by the `Detector` for that slot. Result: at most one framing stage, an ordered coding list, one terminal format stage.

**STEP 2 · DE-FRAME (before compression).** `grpc-web-text` → Base64-decode whole body first; `grpc`/`grpc-web` → walk 5-byte `[flag][BE32 len]` frames using `Be32` (**never** `Protobuf.readLE`, which is little-endian), separating data frames from trailer (`flag&0x80`) / Connect EOS (`flag&0x02`) frames → `Node.FRAMES`; `chunked` → `Chunked.dechunk` (whole-buffer validated) — runs **before** gunzip, matching wire order; `envelope:<pack>` → `EnvelopeStage` parses the protobuf envelope per descriptor and yields the payload field as inner bytes. Whole-body families produce a single synthetic buffer. Trace records framing token, per-frame flags, and preserved special frames verbatim.

**STEP 3 · DECOMPRESS (scope set by framing family).** Whole-body (TikTok/Meta/Twirp/Connect-unary): peel the coding list against the whole payload. Per-frame (gRPC/gRPC-Web/Connect-stream): decompress each data frame with the codec named by `perMessageCodecHeader` + the frame's compressed bit. `EncodingHeaderResolver` unions `Content-Encoding` + `Transfer-Encoding` + `grpc-encoding` + rule `encodingHeaders`. **Magic-first, then verify:** `28 B5 2F FD`→zstd, `1F 8B`→gzip, `04 22 4D 18`→lz4-frame, `FF 06 00 00 73 4E 61 50 70 59`→snappy-framed; zlib by `byte0&0x0F==8 && byte0>>4<=7 && ((byte0<<8|byte1)%31==0)` **verified by full inflate**; `br` and raw-deflate are **header/rule-gated only, never blind-sniffed**. Every trial-decode must consume the whole buffer and yield sane output. Re-sniff the inner buffer and loop to peel stacked layers (catches TikTok hidden-gzip). Trace records each codec + variant (zlib vs raw) + dict id + whether reached by magic or header.

**STEP 4 · FORMAT (terminal).** `printable = Protobuf.asPrintable(buf)` is the text/binary pivot. If a format token was forced (or `schemaPack`/`responseFormat` forces protobuf), use it. Text branch: `json > xml > form+json > form > text` (strict-validated; JSON strips XSSI guard `for(;;);`/`)]}'`/`while(1);` and BOM, supports NDJSON). Binary branch: CBOR self-describe magic `D9 D9 F7` > strict protobuf (whole-buffer consume, field# ∈ [1, 536870911], ≥1 field, confidence score) > msgpack > cbor > raw. `ProtobufStage` overlays field names via `SchemaRenderer`+`ProtoSchema` (from `schemaPack`/`schemaSelect`) while `ProtoText` holds the lossless editable text underneath. `Doc.meta` stores form key order, XSSI guard, ndjson flag, schema path.

**STEP 5 · LABEL + BREADCRUMB.** Label extracted per `action.label` into its template. Breadcrumb = trace steps joined with ` › ` plus resolved schema, e.g. `chunked › gzip › protobuf (tiktok.im/Request)`. `faithfulReencode = AND(coding.canEncode())`.

### ENCODE — `CodecEngine.encode(prior, editedText)` (exact reverse)

**E1 · SERIALIZE.** Terminal format stage: JSON re-emit (re-prepend stripped guard, re-join NDJSON); `ProtoText.parse` for protobuf (unknown fields survive, nested LEN reflow); form/`form+json` re-join preserving recorded key order + which values were JSON + `+`/`%20` convention.

**E2 · RECOMPRESS (inner→outer).** For each recorded coding: if `canEncode()` re-compress with the same codec/variant; else (**brotli, dict-zstd/ttzip**) apply the **universal identity fallback** — emit identity, drop `Content-Encoding` + every `encodingHeaders` alias, set `faithful=false`.

**E3 · RE-FRAME.** gRPC/gRPC-Web recompute `Be32` lengths, set compressed flag, re-append the preserved trailer/EOS frame verbatim, re-base64 for `-text`; chunked re-chunk; `envelope:<pack>` re-encode the protobuf envelope with the edited payload (descriptor-driven, unsigned so edits apply directly).

**E4 · HEADERS LAST.** Set `Content-Length`; apply `rewriteHeader`; mirror `encodingHeaders` the app used (or remove them in fallback); **recompute `SigSpec` LAST over the final wire body** (`Sign.md5UpperHex`) — but only if `sig.enabled` (default false leaves it stale). Editor path covers the viewed tab; `RuleHttpHandler` covers all sent traffic.

**How a rule overrides auto:** a non-null `forcePipeline` replaces STEP 0's sniff entirely; `?`-tokens fall back to identity when their sniff misses; `auto`/`auto-format` re-enters the Detector for just that slot. So a rule can fully pin (`["grpc","protobuf"]`), partially pin (`["dechunk?","gzip?","auto-format"]`), or defer (`["auto"]`).

---

## 5. UI Spec (theme-aware)

### 5.1 "Codec Rules" suite tab (`registerSuiteTab`)

`JSplitPane`: a table view (authoritative-as-projection) over the top, a **raw-JSON view** below — the rule-first centerpiece; both are projections of identical bytes.

- **Table** (`JTable` + `RuleTableModel extends AbstractTableModel` over `ArrayList<Rule>`). Columns: **Enabled · Priority · Name · Dir · Match** (host/path/ct summary) · **Pipeline** (token list or `auto`) · **Pack · Rewrite · Sig · Label**. `getColumnClass(ENABLED)=Boolean.class` → real checkbox; `isCellEditable` true **only** for Enabled (all else via dialog).
- **Buttons:** Add · Edit (modal `RuleDialog` = `JOptionPane` OK/CANCEL form of `JTextField`/`JComboBox` bound to a `Rule` POJO; match lists comma-separated, pipeline an ordered multi-select) · Duplicate · Delete (selected rows descending) · **Move Up / Move Down** (`Collections.swap` + renumber priority — first-match-wins is priority-then-order) · Import · Export · **Reset to built-ins** · "Test on selected message" (runs the rule against the current Proxy item, shows resulting breadcrumb).
- **Raw-JSON sub-tab:** editable `CodeView` of the whole `Ruleset` with **Validate** (`RuleCodec.fromJson` + `StageRegistry.validate` → inline errors) and **Apply**.
- **Import/Export:** `JFileChooser` + `FileNameExtensionFilter("*.json")`, `Files.readString/writeString` — same JSON as persisted.
- Every mutation funnels through one `publish()` = `RuleRegistry.get().set(rows)` **then** `prefs.setString("codec.rules.v1", RuleCodec.toJson(rows))` — atomic, live, persisted immediately (Montoya has no save callback except unload).
- **Theme:** panel/table/button chrome colors pulled from `UIManager.getColor("Panel.background"/"Table.foreground"/"TextArea.background")` so the tab tracks FlatLaf light/dark/custom (caveat: a suite tab is built once and won't live-restyle on toggle; refreshes next launch).

### 5.2 Per-message "Decoded" editor tab

`ExtensionProvidedHttp{Request,Response}Editor` + `CodecWebSocketEditor` over the reused `CodeView`. `isEnabledFor = RuleRegistry.firstMatch(msg)!=null || Detector.looksDecodable(...)`. Layout, top→bottom:

- **Breadcrumb** `JLabel` (always): `Detected: chunked › gzip › protobuf · schema=tiktok.im/Request`, with a dim right-side tag `via rule: TikTok IM [700]` or `via rule: Auto`, and a chip `Re-encode: faithful ✓` / `identity-fallback ⚠ (brotli)` / `read-only (raw)`.
- **Label line** (only when the rule extracts one): `GraphQL: FetchTimelineQuery (doc_id=4926…)` for Meta, `IM message/get_messages` or `Frontier svc=6 method=2 [need_ack]` for TikTok — subsumes MetaAPIDecoder's separate "API Name" section.
- **"Force format ▾"** transient override combo (re-render this one message when a heuristic guessed wrong; not persisted).
- **`CodeView`** (colored, editable iff `EditorCreationContext.editorMode() != READ_ONLY` — Proxy history read-only, Repeater/Intruder editable; this generalizes the current hardcoded `new CodeView(api,true)`). `CodeView` reads `api.userInterface().currentTheme()` at construction (re-created per view, so always current).
- **"Signature: X-Ss-Stub stale ▸ recompute"** toggle, shown only when the matched rule declares a `SigSpec`, making the stale-vs-recomputed tamper choice explicit.

`setRequestResponse` → `engine.decode` → `DecoderPanel.show`. `getRequest/getResponse/getMessage` → `engine.encode` only when `view.isModified()`; unmodified returns original bytes untouched.

---

## 6. Build / Dependencies

```gradle
plugins { id 'java' }
java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }
repositories { mavenCentral() }
dependencies {
    compileOnly 'net.portswigger.burp.extensions:montoya-api:2026.4'   // never bundled
    // Optional pure-Java codecs (bundled → see Open Decisions):
    implementation 'org.brotli:dec:0.1.2'          // brotli DECODE-only, pure Java, ~30 KB
    implementation 'io.airlift:aircompressor:0.27' // zstd/lz4/snappy decode+encode, no-dict, Java 8+, ~180 KB
}
```

- **gzip / zlib-deflate / raw-deflate / HTTP chunked stay JDK-only** — `java.util.zip.GZIPInputStream/GZIPOutputStream` (via `Compression`), `Inflater/Deflater` (new `util.Deflate`, `nowrap=false` zlib / `nowrap=true` raw), `Chunked` verbatim. Zero deps.
- **JSON is dependency-free** — new `burp.codec.util.Json` (recursive-descent parse + `JsonPretty` emit) **replaces Gson**, so MetaAPIDecoder's shadowJar collapses.
- **Brotli decode** via `org.brotli:dec` (no encoder exists → identity fallback on edit). **zstd/lz4/snappy** via `aircompressor` (pure Java, no-dict). Loaded through `OptionalCodec` **reflectively**: if a jar is absent, `canEncode()`/decode degrade to identity fallback rather than a hard dependency — the extension still loads and works.
- **zstd-with-dictionary (ttzip / Meta shared-dict)** is *not* bundled; defeated upstream by the `Accept-Encoding: gzip` rewrite rule. Faithful dict re-encode would need JNI `zstd-jni` (see Open Decisions).
- **Packaging:** a **shadow/fat jar** (Gradle Shadow plugin) *only if* brotli/aircompressor are bundled; otherwise a plain jar. Size impact vs the current ~47 KB:
  - Plain (no optional codecs, reflective-absent): **~55 KB**.
  - + `org.brotli:dec`: **~85 KB**.
  - + `aircompressor`: **~260 KB** total.
  - Recommended default: **bundle both → ~260 KB shadow jar** (small, JNI-free, covers brotli/zstd/lz4/snappy decode + zstd/lz4/snappy encode).

---

## 7. File-by-File Plan

Legend: **REUSE** (unchanged), **MOVE** (relocate, no logic change), **MODIFY**, **NEW**, **DELETE**.

```
src/main/java/burp/
├── tt/protobuf/Protobuf.java ................ REUSE   schema-less wire core
├── tt/protobuf/ProtoText.java ............... REUSE   lossless edit text
├── tt/protobuf/SchemaRenderer.java .......... REUSE   name-overlay render
├── tt/protobuf/ProtoSchema.java ............. REUSE   overlay tree
├── tt/util/Compression.java ................. REUSE   gzip (GzipStage delegates)
├── tt/util/Chunked.java ..................... REUSE   dechunk (ChunkedStage delegates)
├── tt/util/JsonPretty.java .................. REUSE   display + RuleCodec writer
├── tt/util/Sign.java ........................ MODIFY  add hmacSha256B64/sha256Hex helpers
├── tt/ui/CodeView.java ...................... REUSE   editor pane
├── tt/util/Hosts.java ....................... DELETE  host list → data (TikTok rules)
├── tt/TtCodec.java .......................... MODIFY  keep looksForm/looksJson/linesToForm; retire pipeline methods
├── tt/Config.java ........................... DELETE  state now in Preferences
├── tt/http/AcceptEncodingHandler.java ....... DELETE  → rewriteHeader rule
├── tt/http/TtHttpRequestEditor.java ......... DELETE  → CodecRequestEditor
├── tt/http/TtHttpRequestEditorProvider.java . DELETE  → provider in burp.codec.burp
├── tt/http/TtHttpResponseEditor(+Provider) .. DELETE  → CodecResponseEditor(+provider)
├── tt/ws/TtWebSocketEditor(+Provider).java .. DELETE  → CodecWebSocketEditor(+provider)
├── tt/ui/ControlTab.java .................... DELETE  → RulesTab
├── tt/im/ImSchema.java ...................... MOVE→codec/pack/tiktok  rebuilt as tiktok.im SchemaPackDef
├── tt/frontier/Frame.java ................... MOVE→codec/pack/tiktok  descriptor-driven EnvelopeStage
├── tt/frontier/FrameText.java ............... MOVE→codec/pack/tiktok  terminal envelope text
└── tt/TtDecoderExtension.java ............... DELETE  → CodecExtension

src/main/java/burp/codec/
├── core/CodecEngine.java .................... NEW  orchestrator
├── core/Msg.java ........................... NEW  vendor-neutral message view
├── core/Direction.java · Transport.java .... NEW  enums
├── core/DecodeResult.java · DecodeTrace.java NEW  results + reversal record
├── core/Pipeline.java · PipelineCompiler.java NEW  compile + run tokens
├── core/PipelineCtx.java ................... NEW  per-message decode context
├── core/Detector.java ...................... NEW  auto-detect order
├── stage/Stage.java · Kind · Node · Frame .. NEW  SPI + value types
├── stage/StageRegistry.java · StageMeta .... NEW  token→stage, precedence
├── stage/CodecException.java ............... NEW
├── stage/framing/ChunkedStage.java ......... NEW  delegates Chunked
├── stage/framing/RpcFrameStage.java ........ NEW  gRPC/gRPC-web BE32 walker
├── stage/framing/GrpcWebTextStage.java ..... NEW  base64 wrap
├── stage/framing/ConnectStreamStage.java ... NEW  0x02 EOS JSON
├── stage/framing/EventStreamStage.java ..... NEW  AWS vnd.amazon.eventstream
├── stage/framing/EnvelopeStage.java ........ NEW  descriptor-driven WS/protobuf envelope
├── stage/framing/Be32.java ................. NEW  big-endian helpers (NOT Protobuf.writeLE)
├── stage/coding/GzipStage.java ............. NEW  delegates Compression
├── stage/coding/DeflateStage.java .......... NEW  zlib-then-raw fallback
├── stage/coding/ZstdStage.java ............. NEW  aircompressor (+dict via pack)
├── stage/coding/BrotliStage.java ........... NEW  org.brotli:dec, canEncode=false
├── stage/coding/Lz4Stage.java · SnappyStage  NEW  aircompressor frame codecs
├── stage/coding/IdentityStage.java ......... NEW  passthrough / fallback
├── stage/coding/EncodingHeaderResolver.java  NEW  union CE aliases
├── stage/coding/OptionalCodec.java ......... NEW  reflective loader for optional libs
├── stage/format/JsonStage.java ............. NEW  strict + XSSI/BOM/NDJSON
├── stage/format/ProtobufStage.java ......... NEW  SchemaRenderer + ProtoText
├── stage/format/FormStage.java ............. NEW  looksForm/linesToForm
├── stage/format/FormJsonStage.java ......... NEW  generalized MetaAPIDecoder
├── stage/format/XmlStage.java .............. NEW  StAX, DTD/entities OFF (XXE-safe)
├── stage/format/MsgPackStage · CborStage ... NEW  strict recursive detectors
├── stage/format/TextStage · RawStage ....... NEW  text / hex fallback
├── rule/Rule.java · Match · HeaderMatch .... NEW  POJOs
├── rule/Action · HeaderRewrite · SigSpec · LabelSpec  NEW
├── rule/Ruleset.java · RuleCodec.java ...... NEW  JSON doc (via util.Json/JsonPretty)
├── rule/RuleRegistry.java .................. NEW  lock-free singleton
├── pack/Pack.java (SPI) · PackRegistry ..... NEW
├── pack/SchemaPackStore · SchemaPackDef .... NEW
├── pack/EnvelopeDescriptor · LabelExtractor  NEW
├── pack/BuiltinRules.java .................. NEW  seeds default ruleset (resource /codec/builtins.json)
├── pack/tiktok/TikTokPack.java ............. NEW  Pack impl (rules + im schema + frontier envelope)
├── pack/tiktok/ImSchemaDef · FrontierEnvelope NEW  ported from moved classes
├── pack/meta/MetaPack.java ................. NEW  Pack impl (rules + label extractor)
├── util/Json.java .......................... NEW  dep-free JSON parse/emit/validate
├── util/Deflate.java ....................... NEW  zlib/raw inflate/deflate
├── ui/RulesTab.java · RuleTableModel · RuleDialog  NEW
├── ui/DecoderPanel.java · Breadcrumb.java ... NEW
├── burp/CodecExtension.java ................ NEW  BurpExtension entry
├── burp/MsgAdapter.java .................... NEW  Montoya → Msg
├── burp/RuleHttpHandler.java ............... NEW  header rewrite + blanket sig
├── burp/CodecRequestEditor(+Provider).java . NEW
├── burp/CodecResponseEditor(+Provider).java  NEW
└── burp/CodecWebSocketEditor(+Provider).java NEW

src/main/resources/codec/builtins.json ...... NEW  the §3.2 ruleset
```

---

## 8. Migration Steps (each step stays compilable)

1. **Add the generic core untouched.** Introduce `burp.codec.util.Json`, `util.Deflate`, and the `stage/` SPI + `StageRegistry`. Nothing wired yet; existing `TtDecoderExtension` still runs. Compiles.
2. **Port codecs as stages** delegating to reused classes: `GzipStage`→`Compression`, `ChunkedStage`→`Chunked`, `ProtobufStage`→`SchemaRenderer/ProtoText`, plus `DeflateStage`, `JsonStage`, `FormStage`, `TextStage`, `RawStage`. Unit-test each headless (`encode(decode(x))==x`). Compiles.
3. **Add `Detector`, `Pipeline`, `PipelineCompiler`, `CodecEngine`** over those stages. Test decode/encode on captured TikTok + Meta bodies against the *old* tool's output for parity. Compiles; still not registered.
4. **Add rule model + `RuleRegistry` + `RuleCodec` + `Ruleset`** and `resources/codec/builtins.json` (§3.2). Add `BuiltinRules`. Test JSON round-trip. Compiles.
5. **Port vendor packs.** `pack.tiktok`: rebuild `ImSchema` as `tiktok.im` `SchemaPackDef`; move `Frame`/`FrameText` behind `EnvelopeStage` + `tiktok.frontier` descriptor. `pack.meta`: `FormJsonStage` = generalized MetaAPIDecoder (using `util.Json`, no Gson) + label extractor. Verify `tiktok.im` renders identically to `ImSchema` and Meta form+JSON matches Extension B byte-for-byte. Compiles.
6. **Add the new Burp glue** (`CodecExtension`, `MsgAdapter`, editors+providers, `RuleHttpHandler`, `RulesTab`) **but keep the old `TtDecoderExtension` as the registered entry** during bring-up. Load rules from `Preferences("codec.rules.v1")`, seeding `BuiltinRules` on first run; register the unloading flush. Compiles; both extensions installable side by side for A/B.
7. **Cut over the manifest / `BurpExtension` service** to `CodecExtension`. Delete `AcceptEncodingHandler` (now the `tiktok.accept-encoding` rule), `Config`, `Hosts`, and the `Tt*` editors/providers/`ControlTab`/`TtDecoderExtension`. Retire `TtCodec` pipeline methods (keep `looksForm/looksJson/linesToForm`). Full regression: TikTok IM/Frontier/ttzip/X-Ss-Stub/X-Bd + Meta GraphQL all pass via rules.
8. **Enable optional codecs** (`aircompressor`, `org.brotli:dec`) behind `OptionalCodec`; switch to the shadow jar. `grpc.generic`/`grpc.web` rules validated against a gRPC capture. Ship.

At every step the project compiles and at least one working decoder path exists; the risky core (protobuf/gzip/Frontier/form+JSON) is reused verbatim, never rewritten.

---

## 9. Open Decisions for the Human

1. **Bundle brotli + zstd libs in the default jar?**
   - **Recommended: yes, bundle `org.brotli:dec` + `io.airlift:aircompressor`** → ~260 KB shadow jar, JNI-free, gives brotli/zstd/lz4/snappy **decode** and zstd/lz4/snappy **encode** out of the box. Brotli edits fall back to identity (no pure-Java encoder exists).
   - Alternative: ship plain ~55 KB and load these reflectively only if a user drops them on the classpath (smaller, but brotli/zstd bodies are read-only until they do).
2. **Faithful dictionary-zstd / brotli re-encode via JNI?** Bundling `com.github.luben:zstd-jni` (dict decode/encode) + `com.aayushatharva.brotli4j` (brotli encode) adds **per-OS native binaries (~2–5 MB)** and platform-specific packaging. **Recommend deferring to a post-v1 optional "native pack"** gated behind a rule flag; v1 defeats ttzip/dict-zstd upstream via the `Accept-Encoding: gzip` rewrite and uses identity fallback on edit.
3. **Rebrand name.** The neutral root is `burp.codec`; extension display name options: **"Codec Studio"**, **"WireDecoder"**, **"PolyCodec"**, **"Universal Body Decoder"**, or keep a lineage name like **"TT/Meta Codec (vendor-neutral)"**. Pick one for `api.extension().setName(...)` and the suite-tab title.
4. **Rule persistence location.** **Recommend `Persistence.preferences()`** (global, survives restart, shared across projects, trivial import/export) under key `codec.rules.v1`, flushed on every edit + on unload. Offer a later `extensionData()` per-project **override layer** (global base + project delta) only if users ask for project-scoped rules.
5. **How much zstd-dict / Thrift-without-IDL in v1?**
   - **zstd-dict:** wire the `dictionaries` map + `zstd-dict:<name>` token and surface `"zstd (dictionary required)"` when a `Dictionary_ID` frame appears, but ship **no bundled dictionaries** — decode only when a user supplies one (needs JNI, decision #2). Low effort, honest degradation.
   - **Thrift:** binary/compact **structural** decode (field ids+types, no names) is self-describing and cheap to add as a `format` stage; **recommend a v1.1 `ThriftStage`**, not v1. **FlatBuffers is out** (not self-describing; needs `.fbs`). Document both as "structural-only / schema-required" in the UI so users aren't surprised.