# Crimson Blazor Decoder

An OWASP ZAP add-on that decodes and displays Blazor Pack messages sent over WebSocket connections in real time.

## Screenshot

![Crimson Blazor Decoder in ZAP](docs/screenshot.png)

## Why

Blazor Server applications communicate between the browser and server using the Blazor Pack protocol over SignalR WebSockets. The messages are encoded in a binary MessagePack format that is not human-readable. This makes security testing of Blazor Server applications difficult, as the WebSocket traffic in ZAP appears as opaque binary data.

Crimson Blazor Decoder intercepts these WebSocket messages, decodes the MessagePack payload, and presents the data as pretty-printed JSON in a dedicated ZAP panel, enabling security testers to inspect and analyse Blazor Pack traffic.

## Penetration Testing Blazor Applications

Blazor Server is increasingly used in enterprise web applications. During a penetration test, being able to read Blazor Pack traffic is essential for:

- **Understanding application logic** — Blazor Server renders UI server-side and pushes diffs to the client as `RENDER_BATCH` messages. Decoding these reveals which components are rendering, what data they contain, and how the UI state changes in response to user actions.
- **Identifying sensitive data exposure** — Component state, form values, and server responses all travel over the WebSocket. Decoded messages make it straightforward to spot PII, tokens, or business logic that should not be visible to the client.
- **Mapping JS interop calls** — `JS_INTEROP` messages show every JavaScript function invoked by the server, including method names and arguments. This is useful for finding dangerous sinks or undocumented client-side behaviour.
- **Identifying SignalR circuit endpoints** — Circuit Start and Close messages reveal connection identifiers and negotiation details that can be used to test session handling and connection hijacking scenarios.

Without this add-on, all of the above is hidden inside binary MessagePack blobs that appear as garbage in ZAP's WebSockets tab.

## How It Works

1. **Intercepts** WebSocket message frames (both text and binary) through a ZAP WebSocket observer.
2. **Detects** Blazor/SignalR messages using protocol-specific heuristics (binary markers, JSON markers).
3. **Decodes** the MessagePack payload, handling the Blazor Pack multi-value encoding, prefix bytes, and SignalR hub message format.
4. **Displays** the decoded data in a syntax-highlighted JSON view with a hex dump of the raw bytes.
5. **Categorises** messages by type: Render Batch, JS Interop, Circuit Start/Close, Completion, and more.

### Features

- Real-time decoding of Blazor Pack WebSocket traffic
- Syntax-highlighted JSON view with a dark theme
- Raw hex dump view with offset, hex, and ASCII columns
- Message table with colour-coded rows by message type
- Row marking for tracking specific messages
- Export to JSON or raw binary files
- Right-click copy from detail views
- Timestamp tooltips showing human-readable dates

## Building from Source

### Prerequisites

- JDK 17 or later
- A local checkout of [zap-extensions](https://github.com/zaproxy/zap-extensions) with the websocket add-on already built

### Clone and build

```bash
git clone https://github.com/crimsonwall/crimsonblazordecoder.git
cd crimsonblazordecoder
./gradlew jarZapAddOn
```

The built `.zap` file is written to `build/zapAddOn/bin/`.

By default the build looks for `zap-extensions` at `../zap-extensions` (i.e. a sibling directory). If your checkout is elsewhere, pass the path explicitly:

```bash
./gradlew jarZapAddOn -PzapExtensionsDir=/path/to/zap-extensions
```

The websocket add-on jar must already be built inside that checkout:

```bash
cd /path/to/zap-extensions
./gradlew :addOns:websocket:jar
```

### Install in ZAP

Once built, install the add-on via **Tools > Manage Add-ons > Load Add-on from File** and select the `.zap` file, or copy it directly to the ZAP `plugin` directory.

After installation, open the panel via **View > Show Tab > Crimson Blazor Decoder Tab**.

### Requirements

- OWASP ZAP 2.17.0 or later
- The WebSocket add-on (installed by default in ZAP)

## No Warranty

This software is provided "as is" without warranty of any kind, express or implied. In no event shall the authors be liable for any claim, damages, or other liability arising from the use of this software.

## Contributing

If you encounter issues, please feel free to fix them and submit a pull request. Contributions are welcome.
