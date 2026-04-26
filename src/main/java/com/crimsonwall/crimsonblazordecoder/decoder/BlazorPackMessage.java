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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a decoded Blazor Pack message.
 *
 * <p>Blazor Pack is the message format used by Blazor Server for communication between the browser
 * and the server over SignalR WebSockets.
 */
public class BlazorPackMessage {

    private static final int MAX_HEX_DISPLAY = 256;

    private BlazorPackMessageType messageType;
    private int messageId;
    private String rawPayload;
    private byte[] rawBytes;
    private Map<String, Object> decodedData;
    private List<String> references;
    private boolean isBinary;
    private long timestamp;
    private boolean outgoing;

    /**
     * Keys in {@link #decodedData} that contain raw hex/binary payloads and should be excluded from
     * regex matching to avoid false positives (e.g., SA ID numbers matching long hex digit runs).
     */
    private static final java.util.Set<String> RAW_DATA_KEYS =
            java.util.Set.of(
                    "arg_4_1",
                    "arg_4_0",
                    "messagePackData",
                    "rawPayload");

    /** Constructs an empty message with the current timestamp. */
    public BlazorPackMessage() {
        this.decodedData = new LinkedHashMap<>();
        this.references = new ArrayList<>();
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Returns the Blazor Pack message type.
     *
     * @return the message type
     */
    public BlazorPackMessageType getMessageType() {
        return messageType;
    }

    /**
     * Sets the Blazor Pack message type.
     *
     * @param messageType the message type to set
     */
    public void setMessageType(BlazorPackMessageType messageType) {
        this.messageType = messageType;
    }

    /**
     * Returns the message ID (typically the WebSocket channel ID).
     *
     * @return the message ID
     */
    public int getMessageId() {
        return messageId;
    }

    /**
     * Sets the message ID.
     *
     * @param messageId the message ID to set
     */
    public void setMessageId(int messageId) {
        this.messageId = messageId;
    }

    /**
     * Returns the raw payload as a string (JSON or Base64).
     *
     * @return the raw payload string, may be null
     */
    public String getRawPayload() {
        return rawPayload;
    }

    /**
     * Sets the raw payload string.
     *
     * @param rawPayload the raw payload string
     */
    public void setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
    }

    /**
     * Returns a defensive copy of the raw binary payload.
     *
     * @return a copy of the raw bytes, or null if not set
     */
    public byte[] getRawBytes() {
        return rawBytes != null ? rawBytes.clone() : null;
    }

    /**
     * Sets the raw binary payload (stored as a defensive copy).
     *
     * @param rawBytes the raw bytes to store
     */
    public void setRawBytes(byte[] rawBytes) {
        this.rawBytes = rawBytes != null ? rawBytes.clone() : null;
    }

    /**
     * Returns the decoded data fields as a map.
     *
     * @return the decoded data map
     */
    public Map<String, Object> getDecodedData() {
        return decodedData;
    }

    /**
     * Replaces the decoded data map.
     *
     * @param decodedData the new decoded data map
     */
    public void setDecodedData(Map<String, Object> decodedData) {
        this.decodedData = decodedData;
    }

    /**
     * Adds a decoded field to the message data.
     *
     * @param key the field name
     * @param value the decoded value
     */
    public void addDecodedField(String key, Object value) {
        this.decodedData.put(key, value);
    }

    /**
     * Returns the list of reference strings (e.g., JS dependency names).
     *
     * @return the references list
     */
    public List<String> getReferences() {
        return references;
    }

    /**
     * Replaces the references list.
     *
     * @param references the new references list
     */
    public void setReferences(List<String> references) {
        this.references = references;
    }

    /**
     * Adds a reference string (e.g., a JS dependency name).
     *
     * @param reference the reference to add
     */
    public void addReference(String reference) {
        this.references.add(reference);
    }

    /**
     * Returns whether this message was sent as a binary WebSocket frame.
     *
     * @return {@code true} if binary frame
     */
    public boolean isBinary() {
        return isBinary;
    }

    /**
     * Sets whether this message was sent as a binary frame.
     *
     * @param binary {@code true} for binary frame
     */
    public void setBinary(boolean binary) {
        isBinary = binary;
    }

    /**
     * Returns whether this message was sent from client to server.
     *
     * @return {@code true} if outgoing (client-to-server)
     */
    public boolean isOutgoing() {
        return outgoing;
    }

    /**
     * Sets the direction of this message.
     *
     * @param outgoing {@code true} if outgoing (client-to-server)
     */
    public void setOutgoing(boolean outgoing) {
        this.outgoing = outgoing;
    }

    /**
     * Returns the timestamp when this message was captured.
     *
     * @return the epoch millis timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Sets the capture timestamp.
     *
     * @param timestamp the epoch millis timestamp
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Converts the decoded message to a pretty-printed JSON string.
     *
     * @return JSON representation of the message
     */
    public String toPrettyJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"messageType\": \"").append(messageType).append("\",\n");
        json.append("  \"messageId\": ").append(messageId).append(",\n");
        json.append("  \"timestamp\": ").append(timestamp).append(",\n");
        json.append("  \"isBinary\": ").append(isBinary).append(",\n");

        boolean needComma = false;

        if (!decodedData.isEmpty()) {
            json.append("  \"data\": {\n");
            List<String> keys = new ArrayList<>(decodedData.keySet());
            for (int i = 0; i < keys.size(); i++) {
                String key = keys.get(i);
                Object value = decodedData.get(key);
                json.append("    \"").append(DecoderUtils.escapeJson(key)).append("\": ");

                if (value instanceof String) {
                    json.append("\"").append(DecoderUtils.escapeJson((String) value)).append("\"");
                } else if (value instanceof Number) {
                    json.append(value);
                } else if (value instanceof Boolean) {
                    json.append(value);
                } else if (value instanceof Map) {
                    json.append(mapToJson((Map<?, ?>) value, 6));
                } else if (value instanceof List) {
                    json.append(listToJson((List<?>) value, 6));
                } else if (value instanceof byte[]) {
                    json.append("\"")
                            .append(DecoderUtils.truncateHex((byte[]) value, MAX_HEX_DISPLAY))
                            .append("\"");
                } else if (value == null) {
                    json.append("null");
                } else {
                    json.append("\"")
                            .append(DecoderUtils.escapeJson(value.toString()))
                            .append("\"");
                }

                if (i < keys.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            json.append("  }");
            needComma = true;
        }

        if (!references.isEmpty()) {
            if (needComma) json.append(",");
            json.append("\n  \"references\": [\n");
            for (int i = 0; i < references.size(); i++) {
                json.append("    \"")
                        .append(DecoderUtils.escapeJson(references.get(i)))
                        .append("\"");
                if (i < references.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            json.append("  ]");
            needComma = true;
        }

        if (rawPayload != null && !rawPayload.isEmpty()) {
            if (needComma) json.append(",");
            json.append("\n");
            String truncated =
                    rawPayload.length() > 2048
                            ? rawPayload.substring(0, 2048)
                                    + "... ("
                                    + rawPayload.length()
                                    + " chars)"
                            : rawPayload;
            json.append("  \"rawPayload\": \"")
                    .append(DecoderUtils.escapeJson(truncated))
                    .append("\"");
        } else if (needComma) {
            json.append("\n");
        }

        json.append("\n}");
        return json.toString();
    }

    /**
     * Converts the decoded message to a JSON string suitable for regex matching.
     *
     * <p>Only the structured {@code data} field is included — metadata like {@code timestamp},
     * {@code messageId}, and {@code rawPayload} are excluded to avoid false positives.
     *
     * @return a JSON string containing only decoded, human-readable data fields
     */
    public String toDecodedJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");

        if (!decodedData.isEmpty()) {
            List<String> keys = new ArrayList<>(decodedData.keySet());
            boolean first = true;
            for (String key : keys) {
                if (RAW_DATA_KEYS.contains(key)) continue;
                Object value = decodedData.get(key);
                if (!first) {
                    json.append(",\n");
                }
                first = false;
                json.append("  \"").append(DecoderUtils.escapeJson(key)).append("\": ");
                appendDecodedJsonValue(json, value, 4);
            }
            if (!first) {
                json.append("\n");
            }
        }

        if (!references.isEmpty()) {
            if (!decodedData.isEmpty()) {
                json.append(",\n");
            }
            json.append("  \"references\": [\n");
            for (int i = 0; i < references.size(); i++) {
                json.append("    \"")
                        .append(DecoderUtils.escapeJson(references.get(i)))
                        .append("\"");
                if (i < references.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            json.append("  ]\n");
        }

        json.append("}");
        return json.toString();
    }

    /**
     * Appends a JSON value for regex matching, recursing into maps and lists but skipping raw
     * binary data and replacing byte arrays with a placeholder.
     */
    private void appendDecodedJsonValue(StringBuilder sb, Object value, int indent) {
        if (value instanceof String) {
            sb.append("\"").append(DecoderUtils.escapeJson((String) value)).append("\"");
        } else if (value instanceof Number) {
            sb.append(value);
        } else if (value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map) {
            sb.append(mapToDecodedJson((Map<?, ?>) value, indent));
        } else if (value instanceof List) {
            sb.append(listToDecodedJson((List<?>) value, indent));
        } else if (value instanceof byte[]) {
            sb.append("\"[binary data]\"");
        } else if (value == null) {
            sb.append("null");
        } else {
            sb.append("\"").append(DecoderUtils.escapeJson(value.toString())).append("\"");
        }
    }

    private String mapToDecodedJson(Map<?, ?> map, int indent) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        List<?> keys = new ArrayList<>(map.keySet());
        boolean first = true;
        for (Object key : keys) {
            Object value = map.get(key);
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("\n")
                    .append(" ".repeat(indent))
                    .append("\"")
                    .append(DecoderUtils.escapeJson(String.valueOf(key)))
                    .append("\": ");
            appendDecodedJsonValue(sb, value, indent + 2);
        }
        if (!keys.isEmpty()) {
            sb.append("\n").append(" ".repeat(indent - 2));
        }
        sb.append("}");
        return sb.toString();
    }

    private String listToDecodedJson(List<?> list, int indent) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < list.size(); i++) {
            Object value = list.get(i);
            if (i > 0) {
                sb.append(",");
            }
            sb.append("\n").append(" ".repeat(indent));
            appendDecodedJsonValue(sb, value, indent + 2);
        }
        if (!list.isEmpty()) {
            sb.append("\n").append(" ".repeat(indent - 2));
        }
        sb.append("]");
        return sb.toString();
    }

    private String mapToJson(Map<?, ?> map, int indent) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        List<?> keys = new ArrayList<>(map.keySet());
        for (int i = 0; i < keys.size(); i++) {
            Object key = keys.get(i);
            Object value = map.get(key);
            sb.append("\n")
                    .append(" ".repeat(indent))
                    .append("\"")
                    .append(DecoderUtils.escapeJson(String.valueOf(key)))
                    .append("\": ");
            appendJsonValue(sb, value, indent);
            if (i < keys.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("\n").append(" ".repeat(indent - 2)).append("}");
        return sb.toString();
    }

    private String listToJson(List<?> list, int indent) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < list.size(); i++) {
            Object value = list.get(i);
            sb.append("\n").append(" ".repeat(indent));
            appendJsonValue(sb, value, indent);
            if (i < list.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("\n").append(" ".repeat(indent - 2)).append("]");
        return sb.toString();
    }

    private void appendJsonValue(StringBuilder sb, Object value, int indent) {
        if (value instanceof String) {
            sb.append("\"").append(DecoderUtils.escapeJson((String) value)).append("\"");
        } else if (value instanceof Number) {
            sb.append(value);
        } else if (value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map) {
            sb.append(mapToJson((Map<?, ?>) value, indent + 2));
        } else if (value instanceof List) {
            sb.append(listToJson((List<?>) value, indent + 2));
        } else if (value instanceof byte[]) {
            sb.append("\"")
                    .append(DecoderUtils.truncateHex((byte[]) value, MAX_HEX_DISPLAY))
                    .append("\"");
        } else if (value == null) {
            sb.append("null");
        } else {
            sb.append("\"").append(DecoderUtils.escapeJson(value.toString())).append("\"");
        }
    }
}
