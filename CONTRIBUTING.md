# Contributing to PolyProto

Thanks for helping! PolyProto is a small, dependency-light Java codebase — easy to build and extend.

## Build & run

Only **JDK 17** is needed; the Gradle wrapper is committed.

```bash
git clone https://github.com/th3-bl1nd3r/burp-polyproto
cd burp-polyproto
./gradlew shadowJar        # -> build/libs/polyproto.jar   (Windows: gradlew.bat shadowJar)
```

Load `build/libs/polyproto.jar` in Burp → **Extensions → Add → Java**, then reload it after each
rebuild (toggle the extension off/on). CI builds the same jar on every push and PR.

## Project layout

See **[DESIGN.md](DESIGN.md)** for the full architecture. In short: one JSON ruleset selects a
pipeline of reversible `Stage`s (`framing → coding → format`); decode peels layers, encode reverses.

```
core/     engine, pipeline, detector, message model      rule/   rules, registry, JSON codec, labels
stage/    the reversible codecs                            pack/   schema/envelope registry + vendor packs
protobuf/ schema-less wire read/write + tree model         ui/     CodeView, ProtoTreeView, Rules tab
frontier/ Frontier WebSocket Frame                         burp/   extension entry, Montoya adapters
```

## Adding things

- **A codec / format / framing** → new `Stage`. Mirror `stage/coding/GzipStage.java`
  (`sniff`/`decode`/`encode`/`canEncode`), then register its token in `stage/StageDefaults.java`.
  A LEN body should decode losslessly so edit → re-encode round-trips byte-for-byte.
- **Vendor field names** → a `ProtoSchema` in a pack (see `pack/TikTokPack.java`) plus a rule with
  `schemaPack` in `src/main/resources/codec/builtins.json`.
- **Rule capabilities** → the `rule/` model + `rule/RuleCodec.java`; document new fields in DESIGN.md §3.

The reused core (`protobuf/`, `util/Compression`, `util/Chunked`, `util/Json`, `ui/CodeView`) is the
audited, load-bearing part — change it only with a clear reason and a test.

## Ground rules

- **No captured traffic or secrets, ever.** No requests/responses, HAR/pcap/`.burp`, tokens, cookies,
  device IDs, or screenshots with real data. `builtins.json` may contain only public host substrings
  and reverse-engineered field names.
- **No build artifacts** in git (`build/`, `libs/`, `*.jar`, `*.class`, `.gradle/` are ignored).
- **Keep it pure-Java, no JNI**, Montoya stays `compileOnly`.

## Pull requests

1. Branch, make the change, and confirm `./gradlew shadowJar` builds.
2. Load the jar and smoke-test the affected decode/encode path in Burp.
3. Keep the diff focused; match the surrounding code style; explain the *why* in the PR.

## Scope & ethics

PolyProto is for **authorized** security research only. Please don't submit target-specific attack
code or anything that only makes sense for unauthorized use — decoders, schema packs, and rules that
generalize are welcome.
