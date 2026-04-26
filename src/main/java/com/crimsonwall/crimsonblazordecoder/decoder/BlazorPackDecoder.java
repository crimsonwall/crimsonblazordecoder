/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for ZAP.
 *
 * Renico Koen / Crimson Wall / 2026.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.crimsonwall.crimsonblazordecoder.decoder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Decoder for Blazor Pack messages sent over WebSockets.
 *
 * <p>Blazor Pack messages are sent using the SignalR protocol over WebSocket connections. This
 * decoder handles both text (JSON) and binary formats.
 *
 * <p>SignalR message format:
 * https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md
 */
public class BlazorPackDecoder {

    private static final Logger LOGGER = LogManager.getLogger(BlazorPackDecoder.class);

    private final MessagePackDecoder msgPackDecoder = new MessagePackDecoder();
    private final RenderBatchDecoder renderBatchDecoder = new RenderBatchDecoder();

    // SignalR protocol markers
    private static final String TEXT_RECORD_SEPARATOR = "\u001E"; // Record Separator

    // Binary protocol markers
    private static final int BINARY_MESSAGE_FORMAT = 0x01; // Binary data message
    private static final int TEXT_MESSAGE_FORMAT = 0x02; // Text message (UTF-8)
    private static final int PROTOCOL_VERSION = 1;

    // Safety limits
    private static final int MAX_PAYLOAD_SIZE = DecoderUtils.MAX_PAYLOAD_SIZE;
    private static final int MAX_VARINT_VALUE = DecoderUtils.MAX_PAYLOAD_SIZE;
    private static final int MAX_VARINT_BYTES = 5; // 5 bytes max for a valid VarInt
    private static final int MAX_TRY_DECODE_SIZE = 4096; // Max bytes for tryDecodeAsString
    private static final int MAX_LIST_ELEMENTS = 500; // Max elements to process in addListElements

    // Blazor-specific identifiers
    private static final String BLAZOR_CIRCUIT_HEADER = "blazor";

    /**
     * Decode a raw WebSocket payload as a potential Blazor Pack message.
     *
     * @param payload The raw payload bytes from the WebSocket message
     * @param isTextMessage Whether this is a text (true) or binary (false) WebSocket frame
     * @return Decoded Blazor Pack message, or null if not a valid Blazor Pack message
     */
    public BlazorPackMessage decode(byte[] payload, boolean isTextMessage) {
        if (payload == null || payload.length == 0) {
            return null;
        }

        if (payload.length > MAX_PAYLOAD_SIZE) {
            LOGGER.warn(
                    "Payload too large to decode: {} bytes (max {})",
                    payload.length,
                    MAX_PAYLOAD_SIZE);
            return null;
        }

        try {
            BlazorPackMessage result;
            if (isTextMessage) {
                result = decodeTextMessage(payload);
            } else {
                result = decodeBinaryMessage(payload);
            }

            return result;
        } catch (Exception e) {
            LOGGER.debug("Failed to decode Blazor Pack message: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Decode a text-based SignalR/Blazor message.
     *
     * @param payload Raw payload bytes
     * @return Decoded message or null
     */
    private BlazorPackMessage decodeTextMessage(byte[] payload) {
        String text = new String(payload, StandardCharsets.UTF_8);

        BlazorPackMessage message = new BlazorPackMessage();
        message.setBinary(false);

        // Split by record separator if present
        String[] records = text.split(TEXT_RECORD_SEPARATOR);
        boolean atLeastOneParsed = false;
        for (int i = 0; i < records.length; i++) {
            String record = records[i];
            if (record.isEmpty()) {
                continue;
            }

            // Parse JSON message
            try {
                JSONObject json = JSONObject.fromObject(record);
                parseSignalRMessage(json, message);
                atLeastOneParsed = true;
            } catch (Exception e) {
                // Record is not valid JSON - will mark as UNKNOWN below
            }
        }

        // Always store the full raw payload (may contain multiple records)
        message.setRawPayload(text);

        // If no records parsed as valid JSON, mark as UNKNOWN
        if (!atLeastOneParsed) {
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
        }

        return message;
    }

    /**
     * Decode a binary SignalR/Blazor message.
     *
     * <p>Binary SignalR messages follow this format:
     * https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#binary-message-format
     *
     * <p>Blazor Pack uses MessagePack encoding for binary messages after the handshake.
     *
     * @param payload Raw payload bytes
     * @return Decoded message or null
     */
    private BlazorPackMessage decodeBinaryMessage(byte[] payload) {
        if (payload.length < 1) {
            return null;
        }

        int firstByte = payload[0] & 0xFF;

        LOGGER.debug(
                "Decoding binary message, first byte: 0x{}",
                Integer.toHexString(payload[0] & 0xFF));

        // Check if this is a SignalR binary format message (starts with 0x01 or 0x02).
        // NOTE: 0x01 and 0x02 are also valid VarInt length prefixes (values 1 and 2) used in
        // Blazor Pack format. Try SignalR first, fall back to Blazor Pack if it fails.
        if (firstByte == BINARY_MESSAGE_FORMAT || firstByte == TEXT_MESSAGE_FORMAT) {
            BlazorPackMessage result = decodeSignalRBinaryMessage(payload);
            if (result != null) {
                return result;
            }
            // SignalR format failed — first byte is likely a VarInt length prefix, not a format marker
            return decodeMessagePackMessage(payload);
        }

        // Otherwise, try to decode as raw MessagePack (Blazor Pack format)
        return decodeMessagePackMessage(payload);
    }

    /** Decode a SignalR binary format message. */
    private BlazorPackMessage decodeSignalRBinaryMessage(byte[] payload) {
        BlazorPackMessage message = new BlazorPackMessage();
        message.setBinary(true);
        message.setRawBytes(payload.clone());

        ByteBuffer buffer = ByteBuffer.wrap(payload);

        // First byte is the message format type
        int formatType = buffer.get() & 0xFF;

        LOGGER.debug(
                "SignalR binary message format type: 0x{}, remaining bytes: {}",
                Integer.toHexString(formatType),
                buffer.remaining());

        switch (formatType) {
            case BINARY_MESSAGE_FORMAT:
                return decodeBinaryDataMessage(buffer, message);
            case TEXT_MESSAGE_FORMAT:
                return decodeBinaryTextMessage(buffer, message);
            default:
                // Unknown format - try to parse as JSON directly
                LOGGER.debug(
                        "Unknown binary message format: 0x{}, trying direct JSON parse",
                        formatType);
                return tryParseAsJson(payload, message);
        }
    }

    /** Check if a List looks like a Blazor Pack hub message (SignalR format). */
    private boolean isHubMessage(List<Object> list) {
        if (list.isEmpty()) {
            return false;
        }
        // SignalR hub messages start with an integer type (1=Invocation, 2=StreamItem, 3=Completion, etc.)
        Object first = list.get(0);
        return first instanceof Number;
    }

    /** Decode a binary data message (format 0x01). */
    private BlazorPackMessage decodeBinaryDataMessage(
            ByteBuffer buffer, BlazorPackMessage message) {
        try {
            // Read length-prefixed data
            if (buffer.remaining() < 1) {
                return null;
            }

            int length = readVarInt(buffer);
            if (length <= 0 || length > buffer.remaining()) {
                LOGGER.debug("Invalid length: {}, remaining: {}", length, buffer.remaining());
                return null;
            }

            byte[] data = new byte[length];
            buffer.get(data);

            // Try to decode as UTF-8 JSON
            String jsonStr = new String(data, StandardCharsets.UTF_8);
            LOGGER.debug("Binary data message JSON: {}", jsonStr);

            try {
                JSONObject json = JSONObject.fromObject(jsonStr);
                parseSignalRMessage(json, message);
            } catch (Exception e) {
                // Not valid JSON, store as base64
                message.setRawPayload(Base64.getEncoder().encodeToString(data));
                message.setMessageType(BlazorPackMessageType.UNKNOWN);
            }

            return message;
        } catch (Exception e) {
            LOGGER.debug("Error decoding binary data message: {}", e.getMessage());
            return null;
        }
    }

    /** Decode a binary text message (format 0x02). */
    private BlazorPackMessage decodeBinaryTextMessage(
            ByteBuffer buffer, BlazorPackMessage message) {
        try {
            if (buffer.remaining() < 1) {
                return null;
            }

            // Read length-prefixed UTF-8 string
            int length = readVarInt(buffer);

            if (length <= 0 || length > buffer.remaining()) {
                LOGGER.debug("Invalid length: {}, remaining: {}", length, buffer.remaining());
                return null;
            }

            byte[] data = new byte[length];
            buffer.get(data);

            String text = new String(data, StandardCharsets.UTF_8);

            LOGGER.debug("Binary text message: {}", text);

            BlazorPackMessage result = decodeTextMessage(data);
            // Preserve binary flag and raw bytes from the outer wrapper
            result.setBinary(true);
            result.setRawBytes(message.getRawBytes());
            return result;
        } catch (Exception e) {
            LOGGER.debug("Error decoding binary text message: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Decode a raw MessagePack Blazor Pack message.
     *
     * <p>After the handshake, Blazor Pack sends messages directly as MessagePack without the
     * SignalR binary wrapper.
     *
     * <p>The wire format is one or more VarInt-prefixed MessagePack values:
     *
     * <pre>VarInt(len1) + MessagePack(hubMsg1) [+ VarInt(len2) + MessagePack(hubMsg2) ...]</pre>
     */
    private BlazorPackMessage decodeMessagePackMessage(byte[] payload) {
        BlazorPackMessage message = new BlazorPackMessage();
        message.setBinary(true);
        message.setRawBytes(payload.clone());

        LOGGER.debug(
                "Attempting MessagePack decode, first byte: 0x{}, length: {}",
                Integer.toHexString(payload[0] & 0xFF),
                payload.length);

        try {
            // First, try to parse as VarInt-prefixed Blazor Pack messages. This correctly handles
            // multi-message frames where VarInt prefixes > 127 bytes span 2+ bytes and would be
            // misinterpreted by decodeAll() as MessagePack values (fixstr, fixmap, etc.).
            List<List<Object>> hubMessages = tryParseVarIntPrefixedMessages(payload);

            if (hubMessages == null) {
                // VarInt-prefixed parsing failed — fall back to raw decodeAll() approach for
                // single-message frames and edge cases.
                hubMessages = decodeUsingDecodeAll(payload, message);
                if (hubMessages == null) {
                    // decodeAll() also failed — already populated error fields in message
                    return message;
                }
            }

            Object decoded;
            if (hubMessages.isEmpty()) {
                // No hub message found — fall back to raw representation
                List<Object> allValues = msgPackDecoder.decodeAll(payload);
                decoded = allValues;
            } else if (hubMessages.size() == 1) {
                decoded = hubMessages.get(0);
            } else {
                // Multiple hub messages in one frame — wrap them in an outer List so the encoder
                // can round-trip them correctly (list-of-lists signals multi-message format).
                decoded = new ArrayList<>(hubMessages);
                message.addDecodedField("messageCount", hubMessages.size());
                LOGGER.debug(
                        "Multi-message Blazor Pack payload: {} hub messages", hubMessages.size());
            }

            LOGGER.debug("MessagePack decoded successfully: {}", decoded.getClass().getName());

            String jsonStr = msgPackDecoder.toJsonString(decoded);
            message.setRawPayload(jsonStr);

            // Use the last hub message for SignalR type detection; it is usually the most specific
            // when multiple messages are batched together in one frame.
            List<Object> primaryMsg = hubMessages.isEmpty() ? null : hubMessages.get(hubMessages.size() - 1);

            if (primaryMsg != null) {
                parseMessagePackList(primaryMsg, message);
            } else if (decoded instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) decoded;
                parseMessagePackMap(map, message);
            } else {
                message.addDecodedField("value", decoded);
                message.setMessageType(BlazorPackMessageType.UNKNOWN);
            }

            message.addDecodedField("messagePackData", decoded);

        } catch (Exception e) {
            LOGGER.error("Error decoding MessagePack message: {}", e.getMessage(), e);
            message.setRawPayload(Base64.getEncoder().encodeToString(payload));
            message.addDecodedField("hexDump", DecoderUtils.bytesToHex(payload));
            message.addDecodedField("error", e.getMessage());
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
        }

        return message;
    }

    /**
     * Try to parse the payload as VarInt-prefixed Blazor Pack messages.
     *
     * <p>Reads sequential VarInt(length) + MessagePack(hubMsg) chunks. Returns null if the payload
     * doesn't look like valid VarInt-prefixed format (e.g., length overflows remaining bytes).
     *
     * @return list of decoded hub messages, or null if parsing fails
     */
    private List<List<Object>> tryParseVarIntPrefixedMessages(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        List<List<Object>> hubMessages = new ArrayList<>();

        while (buffer.hasRemaining()) {
            // Read VarInt length prefix
            int length = readPackVarInt(buffer);
            if (length <= 0 || length > buffer.remaining()) {
                return null; // Not a valid VarInt-prefixed format
            }

            // Extract the MessagePack bytes for this message
            byte[] msgBytes = new byte[length];
            buffer.get(msgBytes);

            // Decode as MessagePack
            Object decoded = msgPackDecoder.decode(msgBytes);
            if (decoded == null) {
                return null;
            }

            if (decoded instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) decoded;
                if (isHubMessage(list)) {
                    hubMessages.add(list);
                } else {
                    // Try to extract hub messages from nested structure
                    for (Object inner : list) {
                        if (inner instanceof List) {
                            @SuppressWarnings("unchecked")
                            List<Object> innerList = (List<Object>) inner;
                            if (isHubMessage(innerList)) {
                                hubMessages.add(innerList);
                            }
                        }
                    }
                    // If no hub messages found in this value, still record the decoded value
                    // so we don't lose data
                    if (hubMessages.isEmpty()) {
                        return null;
                    }
                }
            } else {
                // Non-list value — could be a standalone value or prefix metadata.
                // This is fine for single-element messages but unusual for the first value.
                // Continue to see if there are more messages.
            }
        }

        return hubMessages;
    }

    /**
     * Read a VarInt using the Blazor Pack / SignalR format (little-endian, 7-bit encoding, bit 7 =
     * continuation).
     *
     * <p>Unlike {@link #readVarInt(ByteBuffer)}, this method does not write debug output.
     */
    private int readPackVarInt(ByteBuffer buffer) {
        int value = 0;
        int shift = 0;
        for (int i = 0; i < MAX_VARINT_BYTES; i++) {
            if (!buffer.hasRemaining()) {
                return -1;
            }
            byte b = buffer.get();
            value |= (b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) {
                if (value > MAX_VARINT_VALUE) {
                    return -1;
                }
                return value;
            }
        }
        return -1; // Too many continuation bytes
    }

    /**
     * Fallback: decode using the raw {@code decodeAll()} approach. This handles edge cases where
     * the VarInt-prefixed parser doesn't apply (e.g., single-message frames where the first byte is
     * a valid MessagePack value).
     *
     * @return list of hub messages, or null if decoding failed entirely (error fields populated in
     *     {@code message})
     */
    private List<List<Object>> decodeUsingDecodeAll(byte[] payload, BlazorPackMessage message) {
        List<Object> allValues = msgPackDecoder.decodeAll(payload);

        if (allValues.isEmpty()) {
            message.setRawPayload(Base64.getEncoder().encodeToString(payload));
            message.addDecodedField("hexDump", DecoderUtils.bytesToHex(payload));
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
            return null;
        }

        // Collect all hub messages (Lists). Non-list values are VarInt length prefixes or
        // extension wrappers — keep the first non-list prefix for metadata only.
        List<List<Object>> hubMessages = new ArrayList<>();
        Object firstPrefix = null;
        for (Object v : allValues) {
            if (v instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> hubMsg = (List<Object>) v;
                if (isHubMessage(hubMsg)) {
                    hubMessages.add(hubMsg);
                } else {
                    for (Object inner : hubMsg) {
                        if (inner instanceof List) {
                            @SuppressWarnings("unchecked")
                            List<Object> innerMsg = (List<Object>) inner;
                            if (isHubMessage(innerMsg)) {
                                hubMessages.add(innerMsg);
                            }
                        }
                    }
                }
            } else if (firstPrefix == null) {
                firstPrefix = v;
            }
        }

        // Store prefix metadata for single-message payloads
        if (hubMessages.size() == 1 && firstPrefix instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> prefixMap = (Map<String, Object>) firstPrefix;
            if (prefixMap.containsKey("extensionType")) {
                message.addDecodedField(
                        "prefixExtensionType",
                        String.valueOf(prefixMap.get("extensionType")));
            }
        }

        return hubMessages;
    }

    /** Parse a MessagePack map to extract Blazor-specific information. */
    private void parseMessagePackMap(Map<String, Object> map, BlazorPackMessage message) {
        // Check for render batch message
        boolean isRenderBatch = false;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof String) {
                String strVal = (String) value;
                if (strVal.contains("updateRootComponents")
                        || strVal.contains("renderBatch")
                        || strVal.contains("UpdateRootComponents")
                        || strVal.contains("GetComponentState")
                        || strVal.contains("DispatchEvent")) {
                    isRenderBatch = true;
                    break;
                }
            } else if (value instanceof byte[]) {
                // Check if binary data is actually JSON (common in Blazor)
                String strVal = tryDecodeAsString((byte[]) value);
                if (strVal != null
                        && (strVal.contains("updateRootComponents")
                                || strVal.contains("renderBatch")
                                || strVal.contains("batchId")
                                || strVal.contains("operations"))) {
                    isRenderBatch = true;
                    break;
                }
            }
        }

        if (isRenderBatch) {
            message.setMessageType(BlazorPackMessageType.RENDER_BATCH);
            message.addDecodedField("messageType", "RenderBatch");
            LOGGER.debug("Parsed as Render Batch");
        }
        // Check for "StartCircuit" message
        else if (map.containsKey("0") || map.containsValue("StartCircuit")) {
            message.setMessageType(BlazorPackMessageType.CIRCUIT_START);
            message.addDecodedField("messageType", "StartCircuit");

            // Extract URLs if present
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof String) {
                    String strVal = (String) value;
                    if (strVal.startsWith("http")) {
                        message.addDecodedField("url_" + entry.getKey(), strVal);
                    }
                } else if (value instanceof byte[]) {
                    byte[] bytes = (byte[]) value;
                    // Might be a connection token or other binary data
                    if (bytes.length > 20) {
                        // Try to decode as UTF-8 string
                        try {
                            String strVal = new String(bytes, StandardCharsets.UTF_8);
                            if (strVal.matches("[a-zA-Z0-9+/=]+")) {
                                message.addDecodedField("connectionToken", strVal);
                            }
                        } catch (Exception e) {
                            // Not a string, keep as bytes
                            message.addDecodedField(entry.getKey(), DecoderUtils.bytesToHex(bytes));
                        }
                    }
                }
            }
        }
        // Check for other message types based on content
        else {
            // Try to find a message type indicator
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if ("type".equals(entry.getKey())) {
                    message.addDecodedField("type", entry.getValue());
                }
            }
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
        }

        // Add all map entries to decoded data
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!message.getDecodedData().containsKey(entry.getKey())) {
                Object value = entry.getValue();
                if (value instanceof byte[]) {
                    message.addDecodedField(entry.getKey(), decodeBytesOrHex((byte[]) value));
                } else if (value instanceof List) {
                    // Process lists to decode any byte arrays inside
                    @SuppressWarnings("unchecked")
                    List<Object> list = (List<Object>) value;
                    List<Object> processedList = new ArrayList<>();
                    for (Object item : list) {
                        if (item instanceof byte[]) {
                            processedList.add(decodeBytesOrHex((byte[]) item));
                        } else {
                            processedList.add(item);
                        }
                    }
                    message.addDecodedField(entry.getKey(), processedList);
                } else {
                    message.addDecodedField(entry.getKey(), value);
                }
            }
        }
    }

    /**
     * Parse a MessagePack list (SignalR hub messages are sent as arrays).
     *
     * <p>SignalR MessagePack format: [messageType, headers, invocationId or None, ...]
     *
     * <p>Message types: 1=Invocation, 2=StreamItem, 3=Completion, 4=StreamInvocation,
     * 5=CancelInvocation, 6=Ping, 7=Close
     */
    private void parseMessagePackList(List<Object> list, BlazorPackMessage message) {
        if (list.isEmpty()) {
            message.addDecodedField("array", list);
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
            return;
        }

        // First element is the SignalR message type
        Object first = list.get(0);
        int signalRType = -1;
        if (first instanceof Number) {
            signalRType = ((Number) first).intValue();
        }

        LOGGER.debug(
                "SignalR MessagePack message type: {}, list size: {}", signalRType, list.size());

        switch (signalRType) {
            case 1: // Invocation
                parseMessagePackInvocation(list, message);
                break;
            case 2: // StreamItem
                message.setMessageType(BlazorPackMessageType.UNKNOWN);
                message.addDecodedField("signalRType", "StreamItem");
                addListElements(list, message);
                break;
            case 3: // Completion
                message.setMessageType(BlazorPackMessageType.COMPLETION);
                message.addDecodedField("signalRType", "Completion");
                addListElements(list, message);
                break;
            case 4: // StreamInvocation
                message.setMessageType(BlazorPackMessageType.JS_INTEROP);
                message.addDecodedField("signalRType", "StreamInvocation");
                parseMessagePackInvocation(list, message);
                break;
            case 5: // CancelInvocation
                message.setMessageType(BlazorPackMessageType.UNKNOWN);
                message.addDecodedField("signalRType", "CancelInvocation");
                addListElements(list, message);
                break;
            case 6: // Ping
                message.setMessageType(BlazorPackMessageType.UNKNOWN);
                message.addDecodedField("signalRType", "Ping");
                break;
            case 7: // Close
                message.setMessageType(BlazorPackMessageType.CIRCUIT_CLOSE);
                message.addDecodedField("signalRType", "Close");
                break;
            default:
                // Try to detect type from content
                detectBlazorMessageType(list, message);
                break;
        }
    }

    /**
     * Parse a MessagePack Invocation message (type 1).
     *
     * <p>Format: [1, headers, invocationId, target, arguments]
     */
    private void parseMessagePackInvocation(List<Object> list, BlazorPackMessage message) {
        String target = null;
        List<Object> arguments = null;

        // Find target (string) and arguments (list) in the array
        for (Object item : list) {
            if (item instanceof String && target == null) {
                String str = (String) item;
                // Skip header maps and invocation IDs - target is a method name
                if (!str.isEmpty() && !str.equals("null")) {
                    target = str;
                }
            } else if (item instanceof List && arguments == null && target != null) {
                @SuppressWarnings("unchecked")
                List<Object> l = (List<Object>) item;
                if (!l.isEmpty()) {
                    arguments = l;
                }
            }
        }

        if (target != null) {
            message.addDecodedField("method", target);

            if (target.contains("RenderBatch") || target.contains("renderBatch")) {
                message.setMessageType(BlazorPackMessageType.RENDER_BATCH);
            } else if (target.contains("StartCircuit")) {
                message.setMessageType(BlazorPackMessageType.CIRCUIT_START);
            } else if (target.contains("UpdateRootComponents")
                    || target.contains("updateRootComponents")) {
                message.setMessageType(BlazorPackMessageType.RENDER_BATCH);
            } else if (target.contains("DispatchEvent")) {
                message.setMessageType(BlazorPackMessageType.JS_INTEROP);
            } else if (target.contains("JS.") || target.startsWith("Microsoft.")) {
                message.setMessageType(BlazorPackMessageType.JS_INTEROP);
            } else {
                message.setMessageType(BlazorPackMessageType.JS_INTEROP);
            }
        } else {
            message.setMessageType(BlazorPackMessageType.JS_INTEROP);
        }

        if (arguments != null) {
            message.addDecodedField("arguments", arguments);
        }

        // Add remaining elements
        addListElements(list, message);
    }

    /** Detect Blazor message type from list content when type number is unknown. */
    private void detectBlazorMessageType(List<Object> list, BlazorPackMessage message) {
        for (Object item : list) {
            if (item instanceof String) {
                String str = (String) item;
                if (str.contains("RenderBatch")
                        || str.contains("renderBatch")
                        || str.contains("UpdateRootComponents")
                        || str.contains("updateRootComponents")) {
                    message.setMessageType(BlazorPackMessageType.RENDER_BATCH);
                    message.addDecodedField("method", str);
                    addListElements(list, message);
                    return;
                }
                if (str.contains("StartCircuit")) {
                    message.setMessageType(BlazorPackMessageType.CIRCUIT_START);
                    message.addDecodedField("method", str);
                    addListElements(list, message);
                    return;
                }
                // Any string that looks like a Blazor method name (PascalCase, contains
                // JS/DotNet/Render/Circuit/Invoke/Event/Component) is a JS interop call
                if (str.contains("JS")
                        || str.contains("DotNet")
                        || str.contains("Invoke")
                        || str.contains("Dispatch")
                        || str.contains("Render")
                        || str.contains("Circuit")
                        || str.contains("Component")
                        || str.contains("OnRender")) {
                    message.setMessageType(BlazorPackMessageType.JS_INTEROP);
                    message.addDecodedField("method", str);
                    addListElements(list, message);
                    return;
                }
            }
        }

        // If the list contains a string that looks like a method target and args,
        // treat it as JS interop anyway
        for (Object item : list) {
            if (item instanceof String) {
                String str = (String) item;
                // PascalCase or dot-separated names like "EndInvokeJSFromDotNet"
                if (str.length() > 3
                        && Character.isUpperCase(str.charAt(0))
                        && !str.startsWith("http")) {
                    message.setMessageType(BlazorPackMessageType.JS_INTEROP);
                    message.addDecodedField("method", str);
                    addListElements(list, message);
                    return;
                }
            }
        }

        // Default
        message.addDecodedField("array", list);
        message.setMessageType(BlazorPackMessageType.UNKNOWN);
    }

    /** Add list elements as decoded fields, processing byte arrays. */
    private void addListElements(List<Object> list, BlazorPackMessage message) {
        int limit = Math.min(list.size(), MAX_LIST_ELEMENTS);
        for (int i = 0; i < limit; i++) {
            Object item = list.get(i);
            String key = "arg_" + i;

            if (item instanceof byte[]) {
                processBytes(key, (byte[]) item, message);
            } else if (item instanceof Map) {
                if (!message.getDecodedData().containsKey(key)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> map = (Map<String, Object>) item;
                    int mapCount = 0;
                    for (Map.Entry<String, Object> entry : map.entrySet()) {
                        if (mapCount++ >= MAX_LIST_ELEMENTS) break;
                        String subKey = "arg_" + i + "_" + entry.getKey();
                        Object val = entry.getValue();
                        if (val instanceof byte[]) {
                            message.addDecodedField(subKey, decodeBytesOrHex((byte[]) val));
                        } else {
                            message.addDecodedField(subKey, val);
                        }
                    }
                }
            } else if (item instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> subList = (List<Object>) item;
                int subLimit = Math.min(subList.size(), MAX_LIST_ELEMENTS);
                for (int j = 0; j < subLimit; j++) {
                    Object subItem = subList.get(j);
                    String subKey = "arg_" + i + "_" + j;
                    if (subItem instanceof byte[]) {
                        processBytes(subKey, (byte[]) subItem, message);
                    } else {
                        message.addDecodedField(subKey, subItem);
                    }
                }
            } else if (!message.getDecodedData().containsKey(key)) {
                message.addDecodedField(key, item);
            }
        }
    }

    /**
     * Processes a byte array: tries decoding as a UTF-8 string, then as render batch binary,
     * falling back to hex.
     *
     * @param key the field key under which to store the result
     * @param bytes the byte array to process
     * @param message the message to add the decoded field to
     */
    private void processBytes(String key, byte[] bytes, BlazorPackMessage message) {
        String decoded = tryDecodeAsString(bytes);
        if (decoded != null) {
            message.addDecodedField(key, decoded);
            return;
        }
        if (message.getMessageType() == BlazorPackMessageType.RENDER_BATCH && bytes.length > 20) {
            Map<String, Object> batchData = renderBatchDecoder.decode(bytes);
            if (!batchData.isEmpty()) {
                message.addDecodedField(key + "_decoded", batchData);
            }
        }
        message.addDecodedField(key, DecoderUtils.bytesToHex(bytes));
    }

    /**
     * Decodes bytes as a UTF-8 string if they are printable, otherwise returns a hex string.
     *
     * @param bytes the byte array to decode
     * @return the decoded string, or the hex representation if not printable
     */
    private Object decodeBytesOrHex(byte[] bytes) {
        String decoded = tryDecodeAsString(bytes);
        return decoded != null ? decoded : DecoderUtils.bytesToHex(bytes);
    }

    /**
     * Try to decode a byte array as a UTF-8 string, returning null if it fails or contains
     * non-printable characters.
     */
    private String tryDecodeAsString(byte[] bytes) {
        if (bytes.length > MAX_TRY_DECODE_SIZE) {
            return null;
        }
        // Phase 1: Fast ASCII scan — reject control characters and detect non-ASCII
        boolean hasNonAscii = false;
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) {
                return null;
            }
            if (b > 0x7E) {
                hasNonAscii = true;
            }
        }
        // Pure ASCII with no control chars — always valid
        if (!hasNonAscii) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
        // Phase 2: Non-ASCII present — decode and round-trip verify for valid UTF-8
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        byte[] reencoded = decoded.getBytes(StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(bytes, reencoded)) {
            return null;
        }
        return decoded;
    }

    /** Try to parse the payload as JSON directly (for unknown binary formats). */
    private BlazorPackMessage tryParseAsJson(byte[] payload, BlazorPackMessage message) {
        try {
            String text = new String(payload, StandardCharsets.UTF_8);
            LOGGER.debug("Trying to parse as JSON: {}", text);

            JSONObject json = JSONObject.fromObject(text);
            BlazorPackMessage result = decodeTextMessage(payload);
            // Preserve binary flag and raw bytes from the outer wrapper
            result.setBinary(true);
            result.setRawBytes(message.getRawBytes());
            return result;
        } catch (Exception e) {
            // Not JSON either - store as base64 for inspection
            message.setRawPayload(Base64.getEncoder().encodeToString(payload));
            message.addDecodedField("hexDump", DecoderUtils.bytesToHex(payload));
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
            LOGGER.debug("Could not parse as JSON, stored as base64");
            return message;
        }
    }

    /** Parse a SignalR JSON message and extract Blazor-specific data. */
    private void parseSignalRMessage(JSONObject json, BlazorPackMessage message) {
        // Cache the type value to avoid repeated parsing
        int signalRType = json.has("type") ? json.getInt("type") : -1;
        if (signalRType >= 0) {
            message.addDecodedField("signalRType", signalRType);
            LOGGER.debug("SignalR message type: {}", signalRType);
        }

        // Check for invocation (method calls) - SignalR type 1
        if (signalRType == 1) {
            parseInvocation(json, message);
            message.setMessageType(BlazorPackMessageType.JS_INTEROP);
            LOGGER.debug("Parsed as JS Interop invocation");
        }
        // Check for render batches
        else if (json.has("renderBatch")) {
            parseRenderBatch(json, message);
            message.setMessageType(BlazorPackMessageType.RENDER_BATCH);
            LOGGER.debug("Parsed as Render Batch");
        }
        // Check for close message
        else if (json.has("Close")) {
            message.setMessageType(BlazorPackMessageType.CIRCUIT_CLOSE);
            message.addDecodedField("closeMessage", json.getString("Close"));
        }
        // Check for protocol handshake
        else if (json.has("protocol") && "blazorpack".equals(json.getString("protocol"))) {
            message.setMessageType(BlazorPackMessageType.PROTOCOL_HANDSHAKE);
            message.addDecodedField("protocol", json.getString("protocol"));
            message.addDecodedField("version", json.get("version"));
            LOGGER.debug("Parsed as Blazor Pack protocol handshake");
            return; // Return early for handshake messages
        }
        // Check for Ping message
        else if (json.has("Ping")) {
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
            message.addDecodedField("ping", true);
        }
        // Check for Completion message - SignalR type 3
        else if (signalRType == 3) {
            parseCompletion(json, message);
        }
        // Check for Stream Item message - SignalR type 2
        else if (signalRType == 2) {
            parseStreamItem(json, message);
        }
        // Generic message
        else {
            message.setMessageType(BlazorPackMessageType.UNKNOWN);
            // Add all fields to decoded data
            for (Object key : json.keySet()) {
                message.addDecodedField(
                        key.toString(), jsonElementToObject(json.get(key.toString())));
            }
            LOGGER.debug("Parsed as generic message with keys: {}", json.keySet());
        }

        // Store raw JSON for reference
        message.setRawPayload(json.toString());
    }

    /** Parse a JS interop invocation message (SignalR type 1). */
    private void parseInvocation(JSONObject json, BlazorPackMessage message) {
        if (json.has("target")) {
            String target = json.getString("target");
            message.addDecodedField("method", target);
            LOGGER.debug("Invocation target: {}", target);
        }
        if (json.has("arguments")) {
            Object argsObj = json.get("arguments");
            if (argsObj instanceof JSONArray) {
                JSONArray args = (JSONArray) argsObj;
                List<Object> argsList = jsonArrayToList(args);
                message.addDecodedField("arguments", argsList);
                LOGGER.debug("Invocation arguments: {}", argsList);
            } else {
                message.addDecodedField("arguments", argsObj);
            }
        }
        if (json.has("invocationId")) {
            message.addDecodedField("invocationId", json.get("invocationId"));
        }
    }

    /** Parse a completion message (SignalR type 3). */
    private void parseCompletion(JSONObject json, BlazorPackMessage message) {
        if (json.has("invocationId")) {
            message.addDecodedField("invocationId", json.get("invocationId"));
        }
        if (json.has("result")) {
            message.addDecodedField("result", jsonElementToObject(json.get("result")));
        }
        if (json.has("error")) {
            message.addDecodedField("error", json.getString("error"));
            message.setMessageType(BlazorPackMessageType.ERROR);
        }
    }

    /** Parse a stream item message (SignalR type 2). */
    private void parseStreamItem(JSONObject json, BlazorPackMessage message) {
        if (json.has("invocationId")) {
            message.addDecodedField("invocationId", json.get("invocationId"));
        }
        if (json.has("item")) {
            message.addDecodedField("item", jsonElementToObject(json.get("item")));
        }
    }

    /** Parse a render batch message. */
    private void parseRenderBatch(JSONObject json, BlazorPackMessage message) {
        if (json.has("renderBatch")) {
            JSONObject batch = json.getJSONObject("renderBatch");
            if (batch.has("components")) {
                message.addDecodedField("components", batch.get("components").toString());
            }
            if (batch.has("references")) {
                JSONArray refs = batch.getJSONArray("references");
                for (int i = 0; i < refs.size(); i++) {
                    message.addReference(refs.get(i).toString());
                }
            }
            if (batch.has("dispatcher")) {
                message.addDecodedField("dispatcher", batch.get("dispatcher"));
            }
        }
    }

    /** Read a variable-length integer from the buffer. */
    private int readVarInt(ByteBuffer buffer) {
        int value = 0;
        int shift = 0;
        byte b;

        for (int i = 0; i < MAX_VARINT_BYTES; i++) {
            if (buffer.remaining() < 1) {
                return -1;
            }
            b = buffer.get();
            value |= (b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) {
                break;
            }
        }

        if (value > MAX_VARINT_VALUE) {
            LOGGER.warn("VarInt value {} exceeds max {}", value, MAX_VARINT_VALUE);
            return -1;
        }

        return value;
    }

    /** Convert JSON element to a Java object. */
    private Object jsonElementToObject(Object element) {
        if (element == null) {
            return null;
        } else if (element instanceof String
                || element instanceof Number
                || element instanceof Boolean) {
            return element;
        } else if (element instanceof JSONArray) {
            return jsonArrayToList((JSONArray) element);
        } else if (element instanceof JSONObject) {
            return jsonObjectToMap((JSONObject) element);
        }
        return element.toString();
    }

    private Map<String, Object> jsonObjectToMap(JSONObject obj) {
        Map<String, Object> map = new HashMap<>();
        for (Object key : obj.keySet()) {
            map.put(key.toString(), jsonElementToObject(obj.get(key.toString())));
        }
        return map;
    }

    private List<Object> jsonArrayToList(JSONArray array) {
        List<Object> list = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            list.add(jsonElementToObject(array.get(i)));
        }
        return list;
    }
}
