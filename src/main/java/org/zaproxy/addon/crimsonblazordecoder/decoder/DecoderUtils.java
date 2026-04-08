/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for OWASP ZAP.
 *
 * Written by Renico Koen. Published by crimsonwall.com in 2026.
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
package org.zaproxy.addon.crimsonblazordecoder.decoder;

/** Shared utility methods for decoder classes. */
final class DecoderUtils {

    private DecoderUtils() {}

    /**
     * Converts a byte array to a lowercase hex string with no separators.
     *
     * @param bytes the byte array to convert
     * @return a hex string representation, two characters per byte
     */
    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
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
            sb.append(String.format("%02x", bytes[i]));
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
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\b", "\\b")
                .replace("\f", "\\f");
    }
}
