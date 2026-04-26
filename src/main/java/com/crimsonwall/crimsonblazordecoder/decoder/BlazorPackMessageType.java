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

/**
 * Message types in the Blazor Pack protocol.
 *
 * <p>Based on the Microsoft.AspNetCore.Components.Server.Circuits package.
 */
public enum BlazorPackMessageType {
    /** Invocation of a JavaScript method from .NET */
    JS_INTEROP(0),

    /** Render batch containing UI updates */
    RENDER_BATCH(1),

    /** Event dispatched from client to server */
    ON_RENDER_COMPLETED(2),

    /** Location changed event */
    LOCATION_CHANGED(3),

    /** Error message */
    ERROR(4),

    /** Protocol handshake/negotiation */
    PROTOCOL_HANDSHAKE(5),

    /** Circuit initialization handshake */
    CIRCUIT_START(6),

    /** Circuit close/termination */
    CIRCUIT_CLOSE(7),

    /** SignalR Completion response */
    COMPLETION(8),

    /** Unknown message type */
    UNKNOWN(-1);

    private final int value;

    /**
     * Creates a message type with the given numeric identifier.
     *
     * @param value the numeric identifier used in the Blazor Pack protocol
     */
    BlazorPackMessageType(int value) {
        this.value = value;
    }

    /**
     * Returns the numeric identifier for this message type.
     *
     * @return the protocol value
     */
    public int getValue() {
        return value;
    }

    /**
     * Returns the message type corresponding to the given numeric identifier, or {@link #UNKNOWN}
     * if no match is found.
     *
     * @param value the numeric identifier to look up
     * @return the matching message type, or {@code UNKNOWN}
     */
    public static BlazorPackMessageType fromValue(int value) {
        for (BlazorPackMessageType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
