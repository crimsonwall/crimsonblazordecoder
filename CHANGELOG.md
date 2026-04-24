# Changelog

All notable changes to this add-on will be documented in this file.

## 1.0.1 - 2026-04-25

### Fixed
- Thread safety: RegexConfig entries list now uses synchronized access to prevent concurrent modification between WebSocket observer and Swing EDT threads
- Security: BlazorPackEncoder.parseJson now validates input length to prevent OOM on oversized inputs
- Performance: DecoderUtils.escapeJson replaces String.format with fast manual hex conversion for control character escaping
- Performance: MessagePackDecoder.trySkipPrefix uses ByteBuffer slicing instead of array copying to reduce allocations
- Performance: MessagePackDecoder.looksLikeJsonString adds recursion depth limit to prevent O(n²) blowup on deeply nested structures

## 1.0.0 - 2026-04-18

### Added
- RegEx tab for defining regex rules matched against decoded message payloads
- 25 default security regex rules (email, IPv4, SA ID, credit card, AWS keys, GCP keys, GitHub tokens, GitLab tokens, JWT, private keys, Stripe, Slack, Discord, SendGrid, Twilio, Azure secrets, generic secrets)
- Regex matches highlighted in yellow in the message list table (highest priority)
- Regex matches highlighted with yellow background in the JSON detail view
- Matching rule names shown as tooltip on yellow-highlighted rows
- Regex rule persistence via ZAP XML configuration
- C->S and S->C column header click toggles all checkboxes in that column
- Tooltips on all tabs and buttons

### Changed
- Tab order: JSON, Raw, RegEx (Modify tab inserted dynamically for outgoing messages)
- Regex matching scoped to decoded data fields only — excludes timestamp, messageId, rawPayload, and raw binary data to prevent false positives
- BoundedCharSequence protects against catastrophic regex backtracking with character access limits
- Input truncated to 5000 chars for regex matching, max 100 rules enforced
- SimpleDateFormat cached as static field for render performance
- MessagePack maps use LinkedHashMap to preserve field insertion order
- Export uses UTF-8 charset explicitly
- File overwrite confirmation dialog on export
- Pretty-printed JSON output uses comma-tracking to avoid malformed trailing commas

### Removed
- API endpoint removed (was permanently disabled)

### Fixed
- Plugin icon now loads correctly (panel calls setIcon in constructor, resource path fixed)
- ExecutorService properly shut down on extension unload
- Negative indent crash in prettyPrintJson guarded with Math.max
- Invalid regex patterns show validation error in the add-rule dialog
- BoundedCharSequence.subSequence now preserves access budget

## 0.2.0 - 2026-04-11

### Added
- Blazor Pack message editing and replay - outgoing messages can now be modified in a JSON editor and sent back to the server
- BlazorPackEncoder and MessagePackEncoder for re-encoding edited messages back to binary Blazor Pack format
- API endpoint (`/crimsonblazordecoder/decode`) for programmatic decoding of Blazor Pack payloads
- Hex dump view showing raw binary payload with offset, hex bytes, and ASCII columns
- Syntax-highlighted JSON view with color-coded keys, strings, and numbers
- Message marking system for flagging messages for later reference
- Export functionality for individual messages (JSON or raw binary)
- Multi-message WebSocket frame support (frames containing multiple Blazor Pack messages)
- Auto-scroll with manual override in the message table
- Real-time status updates and message counting

## 0.1.0 - 2026-04-08

### Added
- Initial release of CrimsonBlazer add-on
- Blazor Pack message decoder
- WebSocket observer for Blazor Pack messages
- Custom UI panel for displaying decoded messages in pretty-printed JSON
