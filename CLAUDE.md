# CLAUDE.md — working on PolyProto

Guidance for Claude Code (and any contributor) working in this repo. Read this first.

## What this is

PolyProto is a **Burp Suite extension (Montoya API, Java 17)** that auto-detects and decodes API
traffic — transport framing, compression, and body format — into a foldable, editable tree, driven
by a JSON **rule engine**. Full architecture: **[DESIGN.md](DESIGN.md)**. User docs: **[README.md](README.md)**.

## First thing on a fresh clone

```bash
./gradlew shadowJar        # builds build/libs/polyproto.jar (downloads Gradle 8.7 + deps on first run)
```

Only **JDK 17** is required — the Gradle wrapper (`./gradlew`) is committed, so you do **not** need
Gradle installed. Montoya is `compileOnly` (Burp provides it at runtime); the pure-Java codecs
(`org.brotli:dec`, `io.airlift:aircompressor`) are bundled into the shadow jar. Load
`build/libs/polyproto.jar` in Burp → **Extensions → Add → Java**.

## Verify a change (do this before committing)

1. `./gradlew test && ./gradlew shadowJar` must succeed (this is the build gate; CI runs both).
2. Load the jar in Burp and exercise the path you touched (decode a real message, edit + replay).
3. The `core/`, `stage/`, `rule/`, `protobuf/` packages have **no Montoya dependency**, so engine logic
   is unit-testable — put tests in `src/test/java` (JUnit 5, test-only deps, never in the shadow jar).
   Use **synthetic** values in tests; never paste captured traffic in, even as a fixture.

## How to extend (the common upgrades)

- **New compression / format / framing** → add a `Stage`. Copy the shape of
  `stage/coding/GzipStage.java` (coding), `stage/format/JsonStage.java` (format), or
  `stage/framing/ChunkedStage.java` (framing), then register the token in `stage/StageDefaults.java`.
  A `Stage` is `sniff` / `decode` / `encode` / `canEncode` — decode peels one layer, encode reverses it.
- **New vendor field names** → add a `ProtoSchema` in a pack (see `pack/TikTokPack.java`) and a rule
  in `src/main/resources/codec/builtins.json` that sets `schemaPack`.
- **New rule behavior** → the `rule/` model + `rule/RuleCodec.java` (JSON ⇄ POJO). Update the schema
  in DESIGN.md §3 if you add a field.
- Keep the **reused core stable**: `protobuf/*`, `util/Compression`, `util/Chunked`, `util/Json`,
  `ui/CodeView`. It's the audited, correctness-critical path — don't rewrite it without a reason and a test.

## Guardrails — do NOT

- **Never commit captured traffic or secrets.** This tool decodes *live* traffic. No requests/responses,
  HAR/pcap/`.burp` files, tokens, cookies, `sessionid`/`sid_guard`/`*-token`, device/install IDs, or
  screenshots containing real data. The bundled `builtins.json` holds only public host substrings and
  RE-derived field names — keep it that way.
- **Never commit build output.** `build/`, `libs/`, `*.jar` (except the committed `gradle-wrapper.jar`),
  `*.class`, and `.gradle/` are in `.gitignore` — do not `git add -f` them.
- **Keep Montoya `compileOnly`.** The shadow jar must not contain `burp/api/montoya/*` — Burp provides it.
- **Don't add heavy/native dependencies.** Bundled codecs are pure-Java, no JNI. Keep it that way so the
  jar stays small and loads on any platform.

## Git hygiene

- Branch for non-trivial changes; run `./gradlew shadowJar` before committing; push only when it builds.
- Commit messages: imperative subject, explain the *why*.
- Releases: `./gradlew shadowJar` then `gh release create vX.Y.Z build/libs/polyproto.jar`. CI
  (`.github/workflows/build.yml`) builds the jar on every push/PR.

## Style

Match the surrounding code: `final` classes, private constructors for utilities, concise Javadoc,
existing naming. Java 17, standard library first, no new runtime deps beyond brotli + aircompressor.
