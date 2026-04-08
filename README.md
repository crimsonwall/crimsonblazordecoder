# Crimson Blazor Decoder

An OWASP ZAP add-on that decodes and displays Blazor Pack messages sent over WebSocket connections in real time.

## Screenshot

![Crimson Blazor Decoder in ZAP](docs/screenshot.png)

## Why

Blazor Server applications communicate between the browser and server using the Blazor Pack protocol over SignalR WebSockets. The messages are encoded in a binary MessagePack format that is not human-readable. This makes security testing of Blazor Server applications difficult, as the WebSocket traffic in ZAP appears as opaque binary data.

Crimson Blazor Decoder intercepts these WebSocket messages, decodes the MessagePack payload, and presents the data as pretty-printed JSON in a dedicated ZAP panel, enabling security testers to inspect and analyse Blazor Pack traffic.

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

## Installation

### From Source

1. Clone this repository inside the `zap-extensions` workspace:
   ```bash
   git clone https://github.com/crimsonwall/crimsonblazordecoder.git
   ```

2. Build the add-on:
   ```bash
   cd zap-extensions
   ./gradlew :addOns:crimsonblazordecoder:build
   ```

3. The built add-on JAR.

4. Install in ZAP via **Tools > Manage Add-ons** and load the JAR file, or copy it to the ZAP `plugin` directory.

### Requirements

- OWASP ZAP 2.17.0 or later
- The WebSocket add-on (installed by default in ZAP)

## No Warranty

This software is provided "as is" without warranty of any kind, express or implied. In no event shall the authors be liable for any claim, damages, or other liability arising from the use of this software.

## Contributing

If you encounter issues, please feel free to fix them and submit a pull request. Contributions are welcome.
