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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decoder for Blazor Server render batch binary data.
 *
 * <p>The render batch is the binary payload sent with JS.RenderBatch messages. It contains
 * component tree updates including element names, attributes, text content, CSS classes, and event
 * handlers.
 *
 * <p>The format uses length-prefixed strings (1 byte length + UTF-8 data) embedded in a binary
 * structure of 4-byte little-endian integers representing component IDs, frame types, and offsets.
 */
public class RenderBatchDecoder {

    private static final int MAX_BATCH_SIZE = 2_000_000;
    private static final int MAX_STRINGS = 1000;
    private static final int MAX_INT_ENTRIES = 5000;

    /**
     * Decode a render batch binary payload into a structured map.
     *
     * @param data The raw render batch binary data
     * @return Map with decoded content: strings, componentIds, htmlContent
     */
    public Map<String, Object> decode(byte[] data) {
        Map<String, Object> result = new LinkedHashMap<>();

        if (data == null || data.length == 0 || data.length > MAX_BATCH_SIZE) {
            return result;
        }

        // Extract all length-prefixed strings
        List<StringEntry> strings = extractStrings(data);
        List<String> stringValues = new ArrayList<>();
        for (StringEntry se : strings) {
            stringValues.add(se.value);
        }
        result.put("strings", stringValues);

        // Extract component IDs (4-byte LE integers that are small positive values)
        List<Integer> componentIds = extractComponentIds(data);
        if (!componentIds.isEmpty()) {
            result.put("componentIds", componentIds);
        }

        // Extract HTML-like content
        String htmlContent = extractHtmlContent(stringValues);
        if (htmlContent != null && !htmlContent.isEmpty()) {
            result.put("htmlContent", htmlContent);
        }

        // Extract CSS classes
        List<String> cssClasses = extractCssClasses(stringValues);
        if (!cssClasses.isEmpty()) {
            result.put("cssClasses", cssClasses);
        }

        // Extract event handlers
        List<String> eventHandlers = extractEventHandlers(stringValues);
        if (!eventHandlers.isEmpty()) {
            result.put("eventHandlers", eventHandlers);
        }

        // Extract Blazor component attributes
        List<String> blazorAttributes = extractBlazorAttributes(stringValues);
        if (!blazorAttributes.isEmpty()) {
            result.put("componentAttributes", blazorAttributes);
        }

        return result;
    }

    /** Extract length-prefixed strings from the binary data. */
    private List<StringEntry> extractStrings(byte[] data) {
        List<StringEntry> strings = new ArrayList<>();
        int i = 0;
        while (i < data.length - 1 && strings.size() < MAX_STRINGS) {
            int len = data[i] & 0xFF;
            if (len >= 1 && len <= 127 && i + 1 + len <= data.length) {
                boolean allPrintable = true;
                boolean hasLetter = false;
                for (int j = 1; j <= len; j++) {
                    int b = data[i + j] & 0xFF;
                    if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) {
                        allPrintable = false;
                        break;
                    }
                    if (b > 0x7E) {
                        allPrintable = false;
                        break;
                    }
                    if (Character.isLetter(b)) hasLetter = true;
                }
                if (allPrintable && hasLetter && len > 1) {
                    String value = new String(data, i + 1, len, StandardCharsets.UTF_8).trim();
                    if (!value.isEmpty()) {
                        strings.add(new StringEntry(i, value));
                    }
                    i += 1 + len;
                    continue;
                }
            }
            i++;
        }
        return strings;
    }

    /**
     * Extract component IDs as small positive 4-byte LE integers from the header region.
     *
     * <p><b>Heuristic:</b> This method scans every 4-byte aligned position in the first 512 bytes
     * and treats any value in the range 1-9999 as a component ID. This is a best-effort heuristic
     * that may produce false positives in arbitrary binary data.
     */
    private List<Integer> extractComponentIds(byte[] data) {
        List<Integer> ids = new ArrayList<>();
        // Component IDs are typically in the first 512 bytes as small positive values
        int limit = Math.min(data.length - 3, 512);
        for (int i = 0; i < limit && ids.size() < MAX_INT_ENTRIES; i += 4) {
            int v =
                    (data[i] & 0xFF)
                            | ((data[i + 1] & 0xFF) << 8)
                            | ((data[i + 2] & 0xFF) << 16)
                            | ((data[i + 3] & 0xFF) << 24);
            // Component IDs are small positive values (1-10000)
            if (v > 0 && v < 10000) {
                ids.add(v);
            }
        }
        return ids;
    }

    /** Extract HTML-like content from strings. */
    private String extractHtmlContent(List<String> strings) {
        StringBuilder html = new StringBuilder();
        for (String s : strings) {
            if (s.contains("<") && s.contains(">")) {
                if (html.length() > 0) html.append("\n");
                html.append(s);
            }
        }
        return html.toString();
    }

    /** Extract CSS class names from strings. */
    private List<String> extractCssClasses(List<String> strings) {
        List<String> classes = new ArrayList<>();
        for (String s : strings) {
            if (s.startsWith("rz-") || (s.contains("-") && !s.contains(" ") && !s.contains("<"))) {
                if (s.length() < 100) {
                    classes.add(s);
                }
            }
        }
        return classes;
    }

    /** Extract event handler references. */
    private List<String> extractEventHandlers(List<String> strings) {
        List<String> handlers = new ArrayList<>();
        for (String s : strings) {
            if (s.startsWith("on") && s.length() < 30 && !s.contains(" ")) {
                handlers.add(s);
            }
            if (s.startsWith("__internal_")) {
                handlers.add(s);
            }
        }
        return handlers;
    }

    /** Extract Blazor component attribute names. */
    private List<String> extractBlazorAttributes(List<String> strings) {
        List<String> attrs = new ArrayList<>();
        for (String s : strings) {
            if (s.matches("^[A-Z][a-zA-Z]+$")
                    && !s.equals("Value")
                    && !s.equals("Body")
                    && !s.equals("Layout")
                    && !s.equals("Resource")) {
                attrs.add(s);
            }
        }
        return attrs;
    }

    /** String entry with offset in the binary data. */
    private static class StringEntry {
        final int offset;
        final String value;

        StringEntry(int offset, String value) {
            this.offset = offset;
            this.value = value;
        }
    }
}
