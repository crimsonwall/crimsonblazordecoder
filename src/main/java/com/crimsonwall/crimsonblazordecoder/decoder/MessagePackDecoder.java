/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for OWASP ZAP.
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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Simple MessagePack decoder for Blazor Pack messages.
 *
 * <p>Implements a subset of the MessagePack specification sufficient for decoding Blazor Pack
 * messages.
 *
 * <p>See: https://github.com/msgpack/msgpack/blob/main/spec.md
 */
public class MessagePackDecoder {

    private static final Logger LOGGER = LogManager.getLogger(MessagePackDecoder.class);

    /** Sentinel object to distinguish MessagePack nil (0xc0) from a decode failure. */
    static final Object NULL_SENTINEL = new Object();

    // Safety limits to prevent crashes on malformed data
    private static final int MAX_DEPTH = 16;
    private static final int MAX_COLLECTION_SIZE = 200000;
    private static final int MAX_STRING_LENGTH = 500000; // ~500 KB
    private static final int MAX_BINARY_LENGTH = 500000; // ~500 KB
    private static final int MAX_TOP_LEVEL_VALUES = 100; // Max values in decodeAll

    // MessagePack format markers
    private static final int NIL = 0xc0;
    private static final int FALSE = 0xc2;
    private static final int TRUE = 0xc3;

    private static final int BIN8 = 0xc4;
    private static final int BIN16 = 0xc5;
    private static final int BIN32 = 0xc6;

    private static final int EXT8 = 0xc7;
    private static final int EXT16 = 0xc8;
    private static final int EXT32 = 0xc9;

    private static final int FIXEXT1 = 0xd4;
    private static final int FIXEXT2 = 0xd5;
    private static final int FIXEXT4 = 0xd6;
    private static final int FIXEXT8 = 0xd7;
    private static final int FIXEXT16 = 0xd8;

    private static final int STR8 = 0xd9;
    private static final int STR16 = 0xda;
    private static final int STR32 = 0xdb;

    private static final int ARRAY16 = 0xdc;
    private static final int ARRAY32 = 0xdd;

    private static final int MAP16 = 0xde;
    private static final int MAP32 = 0xdf;

    // Integer formats
    private static final int UINT8 = 0xcc;
    private static final int UINT16 = 0xcd;
    private static final int UINT32 = 0xce;
    private static final int UINT64 = 0xcf;
    private static final int INT8 = 0xd0;
    private static final int INT16 = 0xd1;
    private static final int INT32 = 0xd2;
    private static final int INT64 = 0xd3;

    // Float formats
    private static final int FLOAT32 = 0xca;
    private static final int FLOAT64 = 0xcb;

    /**
     * Decode a MessagePack-encoded byte array.
     *
     * @param data The MessagePack-encoded data
     * @return Decoded object (Map, List, String, Number, Boolean, or null)
     */
    public Object decode(byte[] data) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            return decodeValue(buffer, 0);
        } catch (Exception e) {
            LOGGER.debug("Failed to decode MessagePack: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Decode all top-level MessagePack values from a byte array.
     *
     * <p>BlazorPack sends a sequence of MessagePack values: first a prefix value (message
     * type/length), then the actual hub message. This method reads all values and combines them
     * into a single list.
     *
     * <p>If the first value is an extension that errors (e.g., EXT16 with an oversized length),
     * this method will attempt to skip just the prefix bytes and decode the remaining payload. The
     * prefix is typically 1-5 bytes (fixint, uint8, int16, etc.) or an extension header.
     *
     * @param data The MessagePack-encoded data
     * @return List of all decoded top-level values
     */
    public List<Object> decodeAll(byte[] data) {
        List<Object> results = new ArrayList<>();
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            while (buffer.hasRemaining() && results.size() < MAX_TOP_LEVEL_VALUES) {
                int posBefore = buffer.position();
                Object value = decodeValue(buffer, 0);
                if (value == null && buffer.position() == posBefore) {
                    // No progress made — true decode failure, stop
                    break;
                }
                // Convert sentinel back to null for consumers
                results.add(value == NULL_SENTINEL ? null : value);
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to decode MessagePack stream: {}", e.getMessage());
        }

        // Retry when the results don't contain a proper SignalR hub message but look like
        // they came from a misinterpreted BlazorPack prefix byte. Prefix bytes that overlap
        // with multi-byte MessagePack formats (BIN8/16/32, FIXEXT, fixmap, fixarray) cause
        // the decoder to consume extra bytes, producing garbled results.
        if (!hasSignalRHubMessage(results)) {
            LOGGER.debug(
                    "No SignalR hub message found in {} results, attempting prefix skip",
                    results.size());
            List<Object> retry = trySkipPrefix(data);
            if (retry != null && !retry.isEmpty() && hasListElement(retry)) {
                return retry;
            }
        }

        return results;
    }

    private boolean hasListElement(List<Object> values) {
        for (Object v : values) {
            if (v instanceof List) return true;
        }
        return false;
    }

    /**
     * Check if the results contain a proper SignalR hub message — a List whose first element is a
     * number in the range 1-7 (the SignalR message type).
     */
    private boolean hasSignalRHubMessage(List<Object> results) {
        for (Object v : results) {
            if (v instanceof List) {
                List<?> list = (List<?>) v;
                if (!list.isEmpty() && list.get(0) instanceof Number) {
                    int type = ((Number) list.get(0)).intValue();
                    if (type >= 1 && type <= 7) return true;
                }
            }
        }
        return false;
    }

    /**
     * Try to decode by skipping a 1-5 byte prefix. Looks for the first byte that starts a valid
     * MessagePack array (0x90-0x9f), map (0x80-0x8f), or positive fixint followed by array/map.
     *
     * <p>Uses ByteBuffer slicing to avoid copying the remaining data into a new array.
     */
    private List<Object> trySkipPrefix(byte[] data) {
        ByteBuffer wrapped = ByteBuffer.wrap(data);
        for (int skip = 1; skip <= Math.min(5, data.length - 1); skip++) {
            int nextByte = data[skip] & 0xFF;
            if ((nextByte >= 0x90 && nextByte <= 0x9f)
                    || (nextByte >= 0x80 && nextByte <= 0x8f)
                    || (nextByte >= 0x01 && nextByte <= 0x07)
                    || nextByte == 0xdc
                    || nextByte == 0xdd) {

                try {
                    ByteBuffer buffer = wrapped.duplicate();
                    buffer.position(skip);
                    List<Object> results = new ArrayList<>();
                    while (buffer.hasRemaining() && results.size() < MAX_TOP_LEVEL_VALUES) {
                        int posBefore = buffer.position();
                        Object value = decodeValue(buffer, 0);
                        if (value == null && buffer.position() == posBefore) break;
                        results.add(value == NULL_SENTINEL ? null : value);
                    }
                    if (!results.isEmpty()) {
                        List<Object> combined = new ArrayList<>();
                        combined.add(data[0] & 0xFF);
                        combined.addAll(results);
                        return combined;
                    }
                } catch (Exception e) {
                    // Try next skip amount
                }
            }
        }
        return null;
    }

    private Object decodeValue(ByteBuffer buffer, int depth) {
        if (depth > MAX_DEPTH) {
            LOGGER.warn("MessagePack decode exceeded max depth {}", MAX_DEPTH);
            return null;
        }

        if (!buffer.hasRemaining()) {
            return null;
        }

        int b = buffer.get() & 0xFF;

        // Positive fixint (0x00 - 0x7f)
        if (b <= 0x7f) {
            return b;
        }

        // Negative fixint (0xe0 - 0xff)
        if (b >= 0xe0) {
            return b - 256;
        }

        // Fixed formats
        if ((b & 0xe0) == 0xa0) {
            // fixstr (0xa0 - 0xbf)
            int length = b & 0x1f;
            return decodeString(buffer, length);
        }

        if ((b & 0xf0) == 0x90) {
            // fixarray (0x90 - 0x9f)
            int size = b & 0x0f;
            return decodeArray(buffer, size, depth + 1);
        }

        if ((b & 0xf0) == 0x80) {
            // fixmap (0x80 - 0x8f)
            int size = b & 0x0f;
            return decodeMap(buffer, size, depth + 1);
        }

        // Variable formats
        switch (b) {
            case NIL:
                return NULL_SENTINEL;
            case FALSE:
                return false;
            case TRUE:
                return true;

            case BIN8:
                return decodeBinary(buffer, readUInt8(buffer));
            case BIN16:
                return decodeBinary(buffer, readUInt16(buffer));
            case BIN32:
                return decodeBinary(buffer, readUInt32(buffer));

            case FLOAT32:
                if (buffer.remaining() < 4) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return buffer.getFloat();

            case FLOAT64:
                if (buffer.remaining() < 8) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return buffer.getDouble();

            case UINT8:
                if (!buffer.hasRemaining()) return null;
                return (int) buffer.get() & 0xFF;
            case UINT16:
                if (buffer.remaining() < 2) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return (int) buffer.getShort() & 0xFFFF;
            case UINT32:
                if (buffer.remaining() < 4) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return buffer.getInt();
            case UINT64:
                if (buffer.remaining() < 8) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return buffer.getLong();
            case INT8:
                if (!buffer.hasRemaining()) return null;
                return (int) buffer.get();
            case INT16:
                if (buffer.remaining() < 2) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return (int) buffer.getShort();
            case INT32:
                if (buffer.remaining() < 4) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return buffer.getInt();
            case INT64:
                if (buffer.remaining() < 8) {
                    buffer.position(buffer.limit());
                    return null;
                }
                return buffer.getLong();

            case EXT8:
                return decodeExtension(buffer, readUInt8(buffer), depth);
            case EXT16:
                return decodeExtension(buffer, readUInt16(buffer), depth);
            case EXT32:
                return decodeExtension(buffer, readUInt32(buffer), depth);

            case FIXEXT1:
                return decodeFixExtension(buffer, 1, depth);
            case FIXEXT2:
                return decodeFixExtension(buffer, 2, depth);
            case FIXEXT4:
                return decodeFixExtension(buffer, 4, depth);
            case FIXEXT8:
                return decodeFixExtension(buffer, 8, depth);
            case FIXEXT16:
                return decodeFixExtension(buffer, 16, depth);

            case STR8:
                return decodeString(buffer, readUInt8(buffer));
            case STR16:
                return decodeString(buffer, readUInt16(buffer));
            case STR32:
                return decodeString(buffer, readUInt32(buffer));

            case ARRAY16:
                return decodeArray(buffer, readUInt16(buffer), depth + 1);
            case ARRAY32:
                return decodeArray(buffer, readUInt32(buffer), depth + 1);

            case MAP16:
                return decodeMap(buffer, readUInt16(buffer), depth + 1);
            case MAP32:
                return decodeMap(buffer, readUInt32(buffer), depth + 1);

            default:
                LOGGER.warn("Unknown MessagePack format: 0x{}", Integer.toHexString(b));
                return null;
        }
    }

    private String decodeString(ByteBuffer buffer, int length) {
        if (length <= 0 || length > buffer.remaining() || length > MAX_STRING_LENGTH) {
            return "";
        }
        byte[] strBytes = new byte[length];
        buffer.get(strBytes);
        return new String(strBytes, StandardCharsets.UTF_8);
    }

    private byte[] decodeBinary(ByteBuffer buffer, int length) {
        if (length <= 0 || length > buffer.remaining() || length > MAX_BINARY_LENGTH) {
            return new byte[0];
        }
        byte[] data = new byte[length];
        buffer.get(data);
        return data;
    }

    private List<Object> decodeArray(ByteBuffer buffer, int size, int depth) {
        if (size > MAX_COLLECTION_SIZE) {
            LOGGER.warn("Array size {} exceeds max {}, truncating", size, MAX_COLLECTION_SIZE);
            size = MAX_COLLECTION_SIZE;
        }
        List<Object> list = new ArrayList<>(Math.min(size, 64));
        for (int i = 0; i < size; i++) {
            if (!buffer.hasRemaining()) {
                break;
            }
            int posBefore = buffer.position();
            Object value = decodeValue(buffer, depth);
            if (value == null && buffer.position() == posBefore) {
                break; // No progress — true failure
            }
            list.add(value == NULL_SENTINEL ? null : value);
        }
        return list;
    }

    private Map<String, Object> decodeMap(ByteBuffer buffer, int size, int depth) {
        if (size > MAX_COLLECTION_SIZE) {
            LOGGER.warn("Map size {} exceeds max {}, truncating", size, MAX_COLLECTION_SIZE);
            size = MAX_COLLECTION_SIZE;
        }
        Map<String, Object> map = new LinkedHashMap<>(Math.min(size * 2, 128));
        for (int i = 0; i < size; i++) {
            if (!buffer.hasRemaining()) {
                break;
            }
            int posBefore = buffer.position();
            Object key = decodeValue(buffer, depth);
            if (key == null && buffer.position() == posBefore) {
                break; // No progress — true failure
            }
            Object value = decodeValue(buffer, depth);
            key = key == NULL_SENTINEL ? null : key;
            value = value == NULL_SENTINEL ? null : value;
            if (key instanceof String) {
                map.put((String) key, value);
            } else if (key != null) {
                map.put(key.toString(), value);
            }
        }
        return map;
    }

    /**
     * Decode a MessagePack extension.
     *
     * <p>Extensions are in the format: [type (1 byte)][data (n bytes)]
     *
     * <p>For Blazor Pack, we skip the extension wrapper and decode the data that follows.
     */
    private Map<String, Object> decodeExtension(ByteBuffer buffer, int length, int depth) {
        int pos = buffer.position();
        LOGGER.debug(
                "decodeExtension: length={}, remaining={}, position={}",
                length,
                buffer.remaining(),
                pos);

        if (length > MAX_BINARY_LENGTH) {
            LOGGER.warn("Extension length {} exceeds max, skipping", length);
            if (buffer.remaining() >= length) {
                buffer.position(buffer.position() + length);
            } else {
                buffer.position(buffer.limit());
            }
            return createErrorMap("Extension too large");
        }

        // Read the extension type
        if (!buffer.hasRemaining()) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("extensionType", -1);
            return result;
        }

        int type = buffer.get() & 0xFF;
        LOGGER.debug("Extension type: {}", type);

        // Calculate how many bytes to skip (length includes the type byte we just read)
        int dataBytes = length - 1;

        if (dataBytes > 0) {
            if (buffer.remaining() < dataBytes) {
                LOGGER.warn(
                        "Not enough bytes for extension data: need={}, have={}",
                        dataBytes,
                        buffer.remaining());
                buffer.position(buffer.limit()); // Consume rest of buffer
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("extensionType", type);
                result.put("error", "Insufficient data");
                return result;
            }

            buffer.position(buffer.position() + dataBytes);
            LOGGER.debug("Skipped {} bytes of extension data", dataBytes);
        }

        if (buffer.hasRemaining()) {
            Object nextValue = decodeValue(buffer, depth + 1);
            LOGGER.debug("Next value after extension: {}", nextValue);

            if (nextValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> result = (Map<String, Object>) nextValue;
                result.put("extensionType", type);
                return result;
            } else if (nextValue instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) nextValue;
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("extensionType", type);
                result.put("array", list);
                return result;
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("extensionType", type);
        result.put("extensionLength", length);
        return result;
    }

    /**
     * Decode a fixed-size MessagePack extension.
     *
     * <p>Fixext formats: FIXEXT1 (1+1), FIXEXT2 (1+2), FIXEXT4 (1+4), FIXEXT8 (1+8), FIXEXT16
     * (1+16)
     *
     * <p>For Blazor Pack/SignalR, the extension data often contains or is followed by the actual
     * MessagePack payload. We try to decode what follows the extension, and if that fails, try to
     * decode the extension data itself.
     */
    private Map<String, Object> decodeFixExtension(ByteBuffer buffer, int dataSize, int depth) {
        if (!buffer.hasRemaining()) {
            return createErrorMap("Insufficient data for extension type");
        }

        int type = buffer.get() & 0xFF;

        // Save position so we can try decoding the extension data itself later
        int dataStart = buffer.position();

        if (dataSize > 0 && buffer.remaining() < dataSize) {
            buffer.position(buffer.limit());
            return createErrorMap("Insufficient data for extension payload");
        }

        // Skip past the extension data bytes
        if (dataSize > 0) {
            buffer.position(buffer.position() + dataSize);
        }

        // First: try to decode the MessagePack data that follows the extension
        if (buffer.hasRemaining()) {
            Object nextValue = decodeValue(buffer, depth + 1);
            if (nextValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> result = (Map<String, Object>) nextValue;
                result.put("extensionType", type);
                return result;
            } else if (nextValue instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) nextValue;
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("extensionType", type);
                result.put("array", list);
                return result;
            }
        }

        // Second: try to decode the extension data itself as MessagePack
        if (dataSize > 0) {
            byte[] extData = new byte[dataSize];
            int savedPos = buffer.position();
            buffer.position(dataStart);
            buffer.get(extData);
            buffer.position(savedPos);

            try {
                Object decoded = decode(extData);
                if (decoded != null) {
                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("extensionType", type);
                    if (decoded instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> decodedMap = (Map<String, Object>) decoded;
                        result.putAll(decodedMap);
                    } else if (decoded instanceof List) {
                        result.put("array", decoded);
                    } else {
                        result.put("value", decoded);
                    }
                    return result;
                }
            } catch (Exception e) {
                LOGGER.debug("Could not decode extension data as MessagePack: {}", e.getMessage());
            }

            // Return raw hex of extension data
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("extensionType", type);
            result.put("extensionHex", DecoderUtils.bytesToHex(extData));
            return result;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("extensionType", type);
        result.put("dataSize", dataSize);
        return result;
    }

    private Map<String, Object> createErrorMap(String error) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("error", error);
        return result;
    }

    private int readUInt8(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
            return 0;
        }
        return buffer.get() & 0xFF;
    }

    private int readUInt16(ByteBuffer buffer) {
        if (buffer.remaining() < 2) {
            buffer.position(buffer.limit());
            return 0;
        }
        return buffer.getShort() & 0xFFFF;
    }

    private int readUInt32(ByteBuffer buffer) {
        if (buffer.remaining() < 4) {
            buffer.position(buffer.limit());
            return 0;
        }
        int value = buffer.getInt();
        // Treat negative values (high bit set) as too large
        if (value < 0) {
            LOGGER.warn("UInt32 value too large, capping to max binary length");
            return MAX_BINARY_LENGTH;
        }
        return value;
    }

    /**
     * Converts a decoded MessagePack object to a JSON-like string representation.
     *
     * <p>byte[] values are encoded using the {"$bin": "hexstring"} format so they round-trip
     * correctly through JSON. This format is recognized by {@link
     * BlazorPackEncoder#parseJson}.
     *
     * <p>List values that appear to be Blazor serializations of JSON strings (arrays containing
     * only primitive types and maps) are encoded as JSON strings using the {"$json": "..."}
     * format. This prevents them from being round-tripped as actual arrays and preserves the
     * original string representation.
     *
     * @param obj the decoded object (Map, List, String, Number, Boolean, byte[], or null)
     * @return a JSON-formatted string representation
     */
    public String toJsonString(Object obj) {
        if (obj == null) {
            return "null";
        } else if (obj instanceof String) {
            return "\"" + DecoderUtils.escapeJson((String) obj) + "\"";
        } else if (obj instanceof Number) {
            return obj.toString();
        } else if (obj instanceof Boolean) {
            return obj.toString();
        } else if (obj instanceof Map) {
            return mapToJson((Map<?, ?>) obj);
        } else if (obj instanceof List) {
            // Check if this list looks like a Blazor-serialized JSON string
            List<?> list = (List<?>) obj;
            if (looksLikeJsonString(list)) {
                // Convert to JSON string and wrap in special format
                String jsonStr = listToJson(list);
                return "{\"$json\":\"" + DecoderUtils.escapeJson(jsonStr) + "\"}";
            }
            return listToJson(list);
        } else if (obj instanceof byte[]) {
            // Use {"$bin": "hexstring"} format for binary data so it round-trips correctly
            return "{\"$bin\":\"" + DecoderUtils.bytesToHex((byte[]) obj) + "\"}";
        }
        return "\"" + obj.toString() + "\"";
    }

    /**
     * Check if a list appears to be a Blazor-serialized JSON string.
     *
     * <p>Blazor serializes JSON strings as MessagePack arrays. We detect this by checking if the
     * list contains only primitive types (numbers, strings, booleans, null) and maps with string
     * keys - essentially anything that could be represented in JSON.
     *
     * <p>Recursion is bounded by {@code maxDepth} to prevent O(n²) blowup on deeply nested
     * structures.
     *
     * @param list the list to check
     * @return true if this looks like a serialized JSON string
     */
    private boolean looksLikeJsonString(List<?> list) {
        return looksLikeJsonString(list, 0);
    }

    private boolean looksLikeJsonString(List<?> list, int depth) {
        if (depth > 4 || list.isEmpty()) {
            return depth <= 4 && !list.isEmpty();
        }

        for (Object item : list) {
            if (item == null || item instanceof String || item instanceof Number
                    || item instanceof Boolean) {
                continue;
            }
            if (item instanceof List) {
                if (!looksLikeJsonString((List<?>) item, depth + 1)) {
                    return false;
                }
                continue;
            }
            if (item instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<?, ?> map = (Map<?, ?>) item;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String)) {
                        return false;
                    }
                    if (entry.getValue() instanceof byte[]) {
                        return false;
                    }
                }
                continue;
            }
            return false;
        }

        return true;
    }

    private String mapToJson(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append("\"")
                    .append(DecoderUtils.escapeJson(String.valueOf(entry.getKey())))
                    .append("\": ");
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(DecoderUtils.escapeJson((String) value)).append("\"");
            } else if (value instanceof Map) {
                sb.append(mapToJson((Map<?, ?>) value));
            } else if (value instanceof List) {
                List<?> list = (List<?>) value;
                if (looksLikeJsonString(list)) {
                    // Wrap in $json format to preserve it as a JSON string
                    sb.append("{\"$json\":\"")
                            .append(DecoderUtils.escapeJson(listToJson(list)))
                            .append("\"}");
                } else {
                    sb.append(listToJson(list));
                }
            } else if (value instanceof byte[]) {
                // Use {"$bin": "hexstring"} format for binary data so it round-trips correctly
                sb.append("{\"$bin\":\"").append(DecoderUtils.bytesToHex((byte[]) value)).append("\"}");
            } else {
                sb.append(toJsonString(value));
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private String listToJson(List<?> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            if (item instanceof String) {
                sb.append("\"").append(DecoderUtils.escapeJson((String) item)).append("\"");
            } else if (item instanceof Map) {
                sb.append(mapToJson((Map<?, ?>) item));
            } else if (item instanceof List) {
                List<?> nestedList = (List<?>) item;
                if (looksLikeJsonString(nestedList)) {
                    // Wrap in $json format to preserve it as a JSON string
                    sb.append("{\"$json\":\"")
                            .append(DecoderUtils.escapeJson(listToJson(nestedList)))
                            .append("\"}");
                } else {
                    sb.append(listToJson(nestedList));
                }
            } else if (item instanceof byte[]) {
                // Use {"$bin": "hexstring"} format for binary data so it round-trips correctly
                sb.append("{\"$bin\":\"").append(DecoderUtils.bytesToHex((byte[]) item)).append("\"}");
            } else {
                sb.append(toJsonString(item));
            }
        }
        sb.append("]");
        return sb.toString();
    }
}
