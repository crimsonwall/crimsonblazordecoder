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

/** Shared utility methods for decoder classes. */
public final class DecoderUtils {

    private DecoderUtils() {}

    /** Maximum payload size to process (10 MB). Shared by the extension observer and decoder. */
    public static final int MAX_PAYLOAD_SIZE = 10_485_760;

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    /**
     * Converts a byte array to a lowercase hex string with no separators.
     *
     * @param bytes the byte array to convert
     * @return a hex string representation, two characters per byte
     */
    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX_CHARS[(b >> 4) & 0x0F]);
            sb.append(HEX_CHARS[b & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * Converts a byte array to hex, truncating if it exceeds the given byte limit.
     *
     * <p>If the input is longer than {@code maxBytes}, only the first {@code maxBytes} are included
     * followed by an overflow indicator showing the total length.
     *
     * @param bytes the byte array to convert
     * @param maxBytes the maximum number of bytes to include in the output
     * @return the hex representation, potentially truncated
     */
    static String truncateHex(byte[] bytes, int maxBytes) {
        if (bytes.length <= maxBytes) {
            return bytesToHex(bytes);
        }
        StringBuilder sb = new StringBuilder(maxBytes * 2 + 30);
        for (int i = 0; i < maxBytes; i++) {
            sb.append(HEX_CHARS[(bytes[i] >> 4) & 0x0F]);
            sb.append(HEX_CHARS[bytes[i] & 0x0F]);
        }
        sb.append("... (").append(bytes.length).append(" bytes total)");
        return sb.toString();
    }

    /**
     * Escapes a string for safe embedding in a JSON value.
     *
     * <p>Escapes backslashes, quotes, and control characters (newline, tab, etc.).
     *
     * @param input the string to escape, or {@code null}
     * @return the escaped string, or an empty string if input is {@code null}
     */
    static String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append("\\u");
                        sb.append(HEX_CHARS[(c >> 12) & 0xF]);
                        sb.append(HEX_CHARS[(c >> 8) & 0xF]);
                        sb.append(HEX_CHARS[(c >> 4) & 0xF]);
                        sb.append(HEX_CHARS[c & 0xF]);
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
