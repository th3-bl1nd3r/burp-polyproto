# PolyProto

**A vendor-neutral API traffic decoder for Burp Suite.**

![License](https://img.shields.io/badge/license-MIT-E89658)
![Java](https://img.shields.io/badge/Java-17-2A3450)
![Burp](https://img.shields.io/badge/Burp-Montoya%20API-2A3450)

PolyProto adds a **Decoded** tab to every HTTP request/response and WebSocket message that
auto-detects and peels the whole stack — transport framing, compression, and body format — into a
readable, **editable** tree. It’s driven by a user-managed **rule engine**, so vendor-specific
behavior is *data*, not code. Built for reverse-engineering and pentesting modern mobile/web APIs
that hide their payloads behind layers of encoding.

> Generalizes two earlier single-vendor tools into one engine: a TikTok decoder and a Meta/GraphQL
> decoder now ship as built-in rule packs.

## What it does

On any message, the **Decoded** tab peels the layers automatically:

| Layer | Coverage |
|---|---|
| **Transport framing** | HTTP chunked, gRPC (5-byte prefix), gRPC-Web (`+text` base64 + trailer), ByteDance **Frontier** WebSocket frames |
| **Content-encoding** | gzip, deflate (zlib + raw), **brotli**, **zstd**, plus IM `__lz4` block for Frontier payloads |
| **Body format** | protobuf, JSON, form-urlencoded, **form + embedded-JSON** (GraphQL), XML |

- **Foldable protobuf tree** with per-token colors, `bytes[N]` chips, and a live timestamp hint on varints.
- **Right-click → decode this field as** protobuf / gzip / base64 / utf-8 — turns an opaque blob into a subtree in place. Plus copy value / hex / field-path.
- **Edit + replay**: switch to the text view, edit, `Ctrl/Cmd+Z` undo/redo, and send from Repeater — PolyProto re-encodes through **every layer** (re-compress, re-chunk, re-frame). Brotli / dictionary-zstd fall back to identity and drop the encoding header.
- **Find bar** that searches the *decoded* text.

## Install

**From a release:** download `polyproto.jar` from [Releases](../../releases), then in Burp →
**Extensions → Add → Java** → select the jar.

**From source:**

```bash
gradle shadowJar        # -> build/libs/polyproto.jar  (bundles brotli + aircompressor, ~0.5 MB)
```

Requires JDK 17. The Montoya API is `compileOnly` (Burp provides it at runtime); the pure-Java
codecs (`org.brotli:dec`, `io.airlift:aircompressor`) are bundled into the shadow jar.

## Rules

Everything vendor-specific is a JSON rule (bundled `builtins.json`, persisted to Burp preferences,
editable in the **PolyProto** suite tab). A rule matches on host / path / method / header /
content-type and can:

- **force a pipeline** (`["dechunk?","gzip?","protobuf"]`) or leave it `auto`,
- apply a **schema pack** (protobuf field names),
- **rewrite a request header** (e.g. defeat a proprietary `Accept-Encoding` so the server replies with gzip),
- recompute a **signature** (off by default — the "is it even checked?" test),
- extract a **label** (e.g. a GraphQL operation name) shown on the tab.

The built-ins reproduce the old TikTok + Meta tools and add generic gRPC/gRPC-Web plus an auto catch-all.

## Architecture

One JSON ruleset → the highest-priority match selects a pipeline of reversible `Stage`s
(`framing → coding → format`) → editable text; `encode` reverses the recorded trace. Auto-detect is
simply the lowest-priority rule. Full design in [DESIGN.md](DESIGN.md).

```
core/    engine, pipeline, detector, message model
stage/   reversible codecs (framing / coding / format)
rule/    rule model, registry, JSON codec, label extractor
pack/    schema/envelope registry + vendor packs (field names)
frontier/  Frontier WebSocket Frame / FrameText
ui/      colored CodeView + find/undo, ProtoTreeView, Rules tab
burp/    extension entry, Montoya adapters, editors, HTTP handler
```

## Not (yet) covered

Connect-RPC / Twirp framing; MessagePack / CBOR bodies; faithful re-compression of brotli and
dictionary-zstd (needs a native lib); Thrift / FlatBuffers (schema-required). All are easy to add
as new `Stage`s — PRs welcome.

## Contributing

Issues and PRs welcome. New decoders are just a `Stage` (see `stage/coding/GzipStage.java` for the
shape); new vendor field-names are a schema pack (see `pack/TikTokPack.java`) plus a rule in
`builtins.json`. Run the build with `gradle shadowJar` and load the jar in Burp to test.

## Disclaimer

PolyProto is a **defensive / research** tool for **authorized** security testing only — your own
apps, bug-bounty programs with explicit scope, CTFs, or lab environments. It is **not affiliated
with, endorsed by, or sponsored by** TikTok, ByteDance, Meta, Google, or any other vendor. The
bundled packs are protobuf **field-name overlays** derived from public reverse engineering; they
contain no proprietary code or credentials. You are responsible for complying with the terms of
service and laws that apply to any traffic you decode.

## License

[MIT](LICENSE) © 2026 Trần Gia Nghĩa ([@th3-bl1nd3r](https://github.com/th3-bl1nd3r))
