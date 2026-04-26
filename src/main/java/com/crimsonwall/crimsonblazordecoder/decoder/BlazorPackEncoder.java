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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Encodes modified Blazor Pack messages back to their binary or text wire format.
 *
 * <p>Accepts a JSON string (as produced by {@link MessagePackDecoder#toJsonString} or from the
 * original text payload) and produces bytes ready to be sent as a WebSocket frame.
 *
 * <p>Binary Blazor Pack format: [VarInt length][MessagePack-encoded hub message]
 *
 * <p>Text SignalR format: [JSON string][record-separator 0x1E]
 *
 * <p>Binary fields ({@code byte[]}) are round-tripped via a tagged JSON object:
 * {@code {"$bin":"hexstring"}}. This format is produced by {@link MessagePackDecoder#toJsonString}
 * and is recognized here to reconstruct the original {@code byte[]} value.
 */
public class BlazorPackEncoder {

    /** SignalR record separator appended to each text message. */
    private static final String RECORD_SEPARATOR = "\u001E";

    /** Maximum nesting depth to prevent stack overflow on deeply nested JSON. */
    private static final int MAX_DEPTH = 32;

    /** Tag key used to represent binary (byte[]) fields in JSON. */
    static final String BIN_TAG = "$bin";

    /** Tag key used to represent JSON strings that were serialized as arrays. */
    static final String JSON_TAG = "$json";

    /** Maximum JSON input length to prevent OOM on unreasonably large inputs. */
    private static final int MAX_JSON_LENGTH = DecoderUtils.MAX_PAYLOAD_SIZE;

    private final MessagePackEncoder msgPackEncoder = new MessagePackEncoder();

    /**
     * Parse a JSON string into a Java object suitable for MessagePack encoding.
     *
     * <p>Uses a hand-written recursive descent parser so that string values whose content happens
     * to look like JSON arrays or objects are never auto-parsed — they remain plain Java
     * {@link String} instances. This avoids the auto-parse behaviour of json-lib.
     *
     * <p>Maps with the single key {@code "$bin"} are converted back to {@code byte[]} so that
     * binary data round-trips correctly through the JSON representation produced by
     * {@link MessagePackDecoder#toJsonString}.
     *
     * @param json the JSON string (array, object, string, number, boolean, or null)
     * @return the parsed Java object (List, Map, byte[], String, Number, Boolean, or null)
     * @throws IllegalArgumentException if the string is not valid JSON
     */
    public Object parseJson(String json) {
        if (json == null) {
            throw new IllegalArgumentException("JSON input is null");
        }
        String trimmed = json.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Empty JSON input");
        }
        if (trimmed.length() > MAX_JSON_LENGTH) {
            throw new IllegalArgumentException(
                    "JSON input too large: " + trimmed.length() + " chars (max " + MAX_JSON_LENGTH + ")");
        }
        try {
            int[] pos = {0};
            Object result = parseValue(trimmed, pos, 0);
            skipWhitespace(trimmed, pos);
            if (pos[0] != trimmed.length()) {
                throw new IllegalArgumentException(
                        "Unexpected trailing characters at position " + pos[0]);
            }
            return result;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Encode a hub message (Java object) as a complete Blazor Pack binary packet.
     *
     * <p>A single hub message is encoded as: VarInt(msgPackLength) + msgPack(hubMessage)
     *
     * <p>A <em>multi-message</em> payload is represented as a List whose first element is itself a
     * List (list-of-lists). Each inner List is encoded as a separate length-prefixed message and
     * the results are concatenated:
     *
     * <pre>VarInt(len1) + msgPack(hubMsg1) + VarInt(len2) + msgPack(hubMsg2) + ...</pre>
     *
     * This matches the format produced by the decoder when it encounters multiple hub messages
     * batched into a single WebSocket frame.
     *
     * @param hubMessage the hub message(s) to encode — a single hub message List/Map, or a
     *     list-of-lists for multi-message payloads
     * @return the complete binary packet as a byte array
     */
    public byte[] encodeAsBlazerPack(Object hubMessage) {
        // Detect multi-message: outer List whose first element is also a List.
        if (hubMessage instanceof List) {
            List<?> outer = (List<?>) hubMessage;
            if (!outer.isEmpty() && outer.get(0) instanceof List) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                for (Object msg : outer) {
                    byte[] msgPackBytes = msgPackEncoder.encode(msg);
                    byte[] prefix = encodeVarInt(msgPackBytes.length);
                    try {
                        out.write(prefix);
                        out.write(msgPackBytes);
                    } catch (java.io.IOException e) {
                        // ByteArrayOutputStream never throws
                    }
                }
                return out.toByteArray();
            }
        }
        // Single message
        byte[] msgPackBytes = msgPackEncoder.encode(hubMessage);
        byte[] prefix = encodeVarInt(msgPackBytes.length);
        byte[] result = new byte[prefix.length + msgPackBytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(msgPackBytes, 0, result, prefix.length, msgPackBytes.length);
        return result;
    }

    /**
     * Encode a text message (JSON string) for sending as a SignalR text frame.
     *
     * <p>Format: jsonText + record-separator (0x1E)
     *
     * @param jsonText the JSON content (without trailing record separator)
     * @return UTF-8 bytes of the message, ready to be sent as a text WebSocket frame
     */
    public byte[] encodeAsTextMessage(String jsonText) {
        String withSep = jsonText.trim() + RECORD_SEPARATOR;
        return withSep.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Encode a variable-length integer using the SignalR VarInt format (little-endian 7-bit
     * encoding).
     *
     * @param value the non-negative integer to encode
     * @return VarInt-encoded bytes
     */
    private byte[] encodeVarInt(int value) {
        byte[] buf = new byte[5]; // VarInt max 5 bytes for 32-bit
        int idx = 0;
        do {
            int b = value & 0x7F;
            value >>>= 7;
            if (value != 0) {
                b |= 0x80;
            }
            buf[idx++] = (byte) b;
        } while (value != 0);
        if (idx == buf.length) return buf;
        byte[] result = new byte[idx];
        System.arraycopy(buf, 0, result, 0, idx);
        return result;
    }

    // -------------------------------------------------------------------------
    // Recursive descent JSON parser
    // -------------------------------------------------------------------------

    private Object parseValue(String s, int[] pos, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON nesting depth exceeds " + MAX_DEPTH);
        }
        skipWhitespace(s, pos);
        if (pos[0] >= s.length()) {
            throw new IllegalArgumentException("Unexpected end of input");
        }
        char c = s.charAt(pos[0]);
        if (c == '"') return parseString(s, pos);
        if (c == '[') return parseArray(s, pos, depth + 1);
        if (c == '{') return parseObject(s, pos, depth + 1);
        if (c == 't') {
            expect(s, pos, "true");
            return Boolean.TRUE;
        }
        if (c == 'f') {
            expect(s, pos, "false");
            return Boolean.FALSE;
        }
        if (c == 'n') {
            expect(s, pos, "null");
            return null;
        }
        if (c == '-' || Character.isDigit(c)) return parseNumber(s, pos);
        throw new IllegalArgumentException(
                "Unexpected character '" + c + "' at position " + pos[0]);
    }

    private String parseString(String s, int[] pos) {
        pos[0]++; // skip opening '"'
        StringBuilder sb = new StringBuilder();
        while (pos[0] < s.length()) {
            char c = s.charAt(pos[0]);
            if (c == '"') {
                pos[0]++; // skip closing '"'
                return sb.toString();
            }
            if (c == '\\') {
                pos[0]++;
                if (pos[0] >= s.length()) break;
                char esc = s.charAt(pos[0]++);
                switch (esc) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'u':
                        if (pos[0] + 4 > s.length()) {
                            throw new IllegalArgumentException("Truncated \\u escape");
                        }
                        String hex = s.substring(pos[0], pos[0] + 4);
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos[0] += 4;
                        break;
                    default:
                        sb.append(esc);
                }
            } else {
                sb.append(c);
                pos[0]++;
            }
        }
        throw new IllegalArgumentException("Unterminated string");
    }

    private List<Object> parseArray(String s, int[] pos, int depth) {
        pos[0]++; // skip '['
        List<Object> list = new ArrayList<>();
        skipWhitespace(s, pos);
        if (pos[0] < s.length() && s.charAt(pos[0]) == ']') {
            pos[0]++;
            return list;
        }
        while (true) {
            list.add(parseValue(s, pos, depth));
            skipWhitespace(s, pos);
            if (pos[0] >= s.length()) {
                throw new IllegalArgumentException("Unterminated array");
            }
            char c = s.charAt(pos[0]++);
            if (c == ']') return list;
            if (c != ',') {
                throw new IllegalArgumentException(
                        "Expected ',' or ']' in array, got '" + c + "'");
            }
        }
    }

    /**
     * Parse a JSON object. If the resulting map has the single key {@code "$bin"} with a string
     * value, the hex string is decoded back to a {@code byte[]}. If it has the single key {@code
     * "$json"} with a string value, the JSON string is parsed as a List/Map.
     */
    private Object parseObject(String s, int[] pos, int depth) {
        pos[0]++; // skip '{'
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace(s, pos);
        if (pos[0] < s.length() && s.charAt(pos[0]) == '}') {
            pos[0]++;
            return map;
        }
        while (true) {
            skipWhitespace(s, pos);
            if (pos[0] >= s.length() || s.charAt(pos[0]) != '"') {
                throw new IllegalArgumentException(
                        "Expected string key at position " + pos[0]);
            }
            String key = parseString(s, pos);
            skipWhitespace(s, pos);
            if (pos[0] >= s.length() || s.charAt(pos[0]++) != ':') {
                throw new IllegalArgumentException("Expected ':' after key");
            }
            Object value = parseValue(s, pos, depth);
            map.put(key, value);
            skipWhitespace(s, pos);
            if (pos[0] >= s.length()) {
                throw new IllegalArgumentException("Unterminated object");
            }
            char c = s.charAt(pos[0]++);
            if (c == '}') break;
            if (c != ',') {
                throw new IllegalArgumentException(
                        "Expected ',' or '}' in object, got '" + c + "'");
            }
        }
        // Recognize {"$bin": "hexstring"} and convert back to byte[].
        if (map.size() == 1 && map.containsKey(BIN_TAG)) {
            Object hexVal = map.get(BIN_TAG);
            if (hexVal instanceof String) {
                return hexStringToBytes((String) hexVal);
            }
        }
        // Recognize {"$json": "jsonstring"} and parse the JSON string.
        if (map.size() == 1 && map.containsKey(JSON_TAG)) {
            Object jsonVal = map.get(JSON_TAG);
            if (jsonVal instanceof String) {
                // Continue parsing with the same depth to prevent unbounded recursion
                int[] pos2 = {0};
                String inner = (String) jsonVal;
                Object parsed = parseValue(inner, pos2, depth);
                skipWhitespace(inner, pos2);
                if (pos2[0] != inner.length()) {
                    throw new IllegalArgumentException(
                            "Unexpected trailing characters in $json value at position " + pos2[0]);
                }
                return parsed;
            }
        }
        return map;
    }

    private Number parseNumber(String s, int[] pos) {
        int start = pos[0];
        if (s.charAt(pos[0]) == '-') pos[0]++;
        while (pos[0] < s.length() && Character.isDigit(s.charAt(pos[0]))) pos[0]++;
        boolean isFloat = false;
        if (pos[0] < s.length() && s.charAt(pos[0]) == '.') {
            isFloat = true;
            pos[0]++;
            while (pos[0] < s.length() && Character.isDigit(s.charAt(pos[0]))) pos[0]++;
        }
        if (pos[0] < s.length() && (s.charAt(pos[0]) == 'e' || s.charAt(pos[0]) == 'E')) {
            isFloat = true;
            pos[0]++;
            if (pos[0] < s.length()
                    && (s.charAt(pos[0]) == '+' || s.charAt(pos[0]) == '-')) {
                pos[0]++;
            }
            while (pos[0] < s.length() && Character.isDigit(s.charAt(pos[0]))) pos[0]++;
        }
        String numStr = s.substring(start, pos[0]);
        if (isFloat) {
            return Double.parseDouble(numStr);
        }
        try {
            long l = Long.parseLong(numStr);
            if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) {
                return (int) l;
            }
            return l;
        } catch (NumberFormatException e) {
            return Double.parseDouble(numStr);
        }
    }

    private void skipWhitespace(String s, int[] pos) {
        while (pos[0] < s.length() && Character.isWhitespace(s.charAt(pos[0]))) {
            pos[0]++;
        }
    }

    private void expect(String s, int[] pos, String expected) {
        if (!s.startsWith(expected, pos[0])) {
            throw new IllegalArgumentException(
                    "Expected '" + expected + "' at position " + pos[0]);
        }
        pos[0] += expected.length();
    }

    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Odd-length hex string in $bin value");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException(
                        "Invalid hex character in $bin value at position " + i);
            }
            data[i / 2] = (byte) ((hi << 4) | lo);
        }
        return data;
    }
}
