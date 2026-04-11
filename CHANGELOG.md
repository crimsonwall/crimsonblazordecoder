# Changelog

All notable changes to this add-on will be documented in this file.

## 0.2.0 - 2026-04-09

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
