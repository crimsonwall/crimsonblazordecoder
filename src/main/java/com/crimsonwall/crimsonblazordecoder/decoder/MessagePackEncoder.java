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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Encodes Java objects to MessagePack binary format.
 *
 * <p>Supports the subset of MessagePack types used by Blazor Pack / SignalR:
 * null, Boolean, Integer, Long, Double, String, byte[], List, and Map.
 *
 * <p>See: https://github.com/msgpack/msgpack/blob/main/spec.md
 */
public class MessagePackEncoder {

    private static final int MAX_DEPTH = 32;
    private static final int MAX_COLLECTION_SIZE = 200000;
    private static final int MAX_STRING_LENGTH = 500000;

    /**
     * Encode a Java object to its MessagePack binary representation.
     *
     * @param value the value to encode (null, Boolean, Number, String, byte[], List, or Map)
     * @return MessagePack-encoded bytes
     */
    public byte[] encode(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            encodeValue(out, value, 0);
        } catch (IOException e) {
            // ByteArrayOutputStream never throws IOException
        }
        return out.toByteArray();
    }

    private void encodeValue(ByteArrayOutputStream out, Object value, int depth) throws IOException {
        if (depth > MAX_DEPTH) {
            throw new IOException("MessagePack encoding depth exceeds " + MAX_DEPTH);
        }
        if (value == null) {
            out.write(0xc0); // nil
        } else if (value instanceof Boolean) {
            out.write((Boolean) value ? 0xc3 : 0xc2); // true / false
        } else if (value instanceof Long) {
            encodeLong(out, (Long) value);
        } else if (value instanceof Integer) {
            encodeInt(out, (Integer) value);
        } else if (value instanceof Number) {
            double d = ((Number) value).doubleValue();
            long l = (long) d;
            if (d == l) {
                encodeLong(out, l);
            } else {
                // float64
                out.write(0xcb);
                long bits = Double.doubleToRawLongBits(d);
                writeInt64(out, bits);
            }
        } else if (value instanceof String) {
            encodeString(out, (String) value);
        } else if (value instanceof byte[]) {
            encodeBinary(out, (byte[]) value);
        } else if (value instanceof List) {
            encodeArray(out, (List<?>) value, depth + 1);
        } else if (value instanceof Map) {
            encodeMap(out, (Map<?, ?>) value, depth + 1);
        } else {
            // Fallback: encode toString() as a string
            encodeString(out, value.toString());
        }
    }

    private void encodeInt(ByteArrayOutputStream out, int value) throws IOException {
        if (value >= 0 && value <= 0x7f) {
            out.write(value); // positive fixint
        } else if (value < 0 && value >= -32) {
            out.write(value & 0xFF); // negative fixint (0xe0 - 0xff)
        } else if (value >= 0 && value <= 0xFF) {
            out.write(0xcc);
            out.write(value); // uint8
        } else if (value >= 0 && value <= 0xFFFF) {
            out.write(0xcd);
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF); // uint16
        } else if (value >= 0) {
            out.write(0xce);
            writeInt32(out, value); // uint32
        } else if (value >= -128) {
            out.write(0xd0);
            out.write(value & 0xFF); // int8
        } else if (value >= -32768) {
            out.write(0xd1);
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF); // int16
        } else {
            out.write(0xd2);
            writeInt32(out, value); // int32
        }
    }

    private void encodeLong(ByteArrayOutputStream out, long value) throws IOException {
        if (value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) {
            encodeInt(out, (int) value);
        } else if (value >= 0 && value <= 0xFFFFFFFFL) {
            out.write(0xce);
            writeInt32(out, (int) value); // uint32
        } else {
            out.write(0xd3);
            writeInt64(out, value); // int64
        }
    }

    private void encodeString(ByteArrayOutputStream out, String s) throws IOException {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_LENGTH) {
            throw new IOException("String too long for MessagePack encoding: " + bytes.length);
        }
        int len = bytes.length;
        if (len <= 31) {
            out.write(0xa0 | len); // fixstr
        } else if (len <= 0xFF) {
            out.write(0xd9);
            out.write(len); // str8
        } else if (len <= 0xFFFF) {
            out.write(0xda);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF); // str16
        } else {
            out.write(0xdb);
            writeInt32(out, len); // str32
        }
        out.write(bytes);
    }

    private void encodeBinary(ByteArrayOutputStream out, byte[] data) throws IOException {
        int len = data.length;
        if (len <= 0xFF) {
            out.write(0xc4);
            out.write(len); // bin8
        } else if (len <= 0xFFFF) {
            out.write(0xc5);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF); // bin16
        } else {
            out.write(0xc6);
            writeInt32(out, len); // bin32
        }
        out.write(data);
    }

    private void encodeArray(ByteArrayOutputStream out, List<?> list, int depth) throws IOException {
        int size = list.size();
        if (size > MAX_COLLECTION_SIZE) {
            throw new IOException("Array size exceeds max: " + size);
        }
        if (size <= 15) {
            out.write(0x90 | size); // fixarray
        } else if (size <= 0xFFFF) {
            out.write(0xdc);
            out.write((size >> 8) & 0xFF);
            out.write(size & 0xFF); // array16
        } else {
            out.write(0xdd);
            writeInt32(out, size); // array32
        }
        for (Object item : list) {
            encodeValue(out, item, depth);
        }
    }

    private void encodeMap(ByteArrayOutputStream out, Map<?, ?> map, int depth) throws IOException {
        int size = map.size();
        if (size > MAX_COLLECTION_SIZE) {
            throw new IOException("Map size exceeds max: " + size);
        }
        if (size <= 15) {
            out.write(0x80 | size); // fixmap
        } else if (size <= 0xFFFF) {
            out.write(0xde);
            out.write((size >> 8) & 0xFF);
            out.write(size & 0xFF); // map16
        } else {
            out.write(0xdf);
            writeInt32(out, size); // map32
        }
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            encodeValue(out, entry.getKey(), depth);
            encodeValue(out, entry.getValue(), depth);
        }
    }

    private void writeInt32(ByteArrayOutputStream out, int value) throws IOException {
        out.write((value >> 24) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private void writeInt64(ByteArrayOutputStream out, long value) throws IOException {
        out.write((int) (value >> 56) & 0xFF);
        out.write((int) (value >> 48) & 0xFF);
        out.write((int) (value >> 40) & 0xFF);
        out.write((int) (value >> 32) & 0xFF);
        out.write((int) (value >> 24) & 0xFF);
        out.write((int) (value >> 16) & 0xFF);
        out.write((int) (value >> 8) & 0xFF);
        out.write((int) value & 0xFF);
    }
}
