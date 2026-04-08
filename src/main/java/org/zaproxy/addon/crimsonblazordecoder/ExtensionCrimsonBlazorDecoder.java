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
package org.zaproxy.addon.crimsonblazordecoder;

import java.awt.EventQueue;
import java.net.URI;
import java.net.URL;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.crimsonblazordecoder.decoder.BlazorPackDecoder;
import org.zaproxy.addon.crimsonblazordecoder.decoder.BlazorPackMessage;
import org.zaproxy.addon.crimsonblazordecoder.ui.CrimsonBlazorDecoderPanel;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.utils.DisplayUtils;

/**
 * Main extension class for the Crimson Blazor Decoder add-on.
 *
 * <p>This extension observes WebSocket messages, detects Blazor Pack messages (used by Blazor
 * Server applications), decodes them, and displays them in a dedicated UI panel with pretty-printed
 * JSON.
 */
public class ExtensionCrimsonBlazorDecoder extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionCrimsonBlazorDecoder.class);

    public static final String NAME = "ExtensionCrimsonBlazorDecoder";

    /** The i18n prefix. */
    protected static final String PREFIX = "crimsonblazordecoder";

    /** Observer order - should receive messages after other processors. */
    private static final int OBSERVER_ORDER = 10000;

    /** Maximum payload size to process (10 MB). */
    private static final int MAX_PAYLOAD_SIZE = 10_485_760;

    private ExtensionWebSocket extensionWebSocket;
    private BlazorPackDecoder decoder;
    private CrimsonBlazorDecoderPanel blazerPanel;
    private CrimsonBlazorDecoderObserver webSocketObserver;
    private CrimsonBlazorDecoderAPI api;

    /** Creates the extension and sets the i18n prefix. */
    public ExtensionCrimsonBlazorDecoder() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.decoder = new BlazorPackDecoder();
        this.webSocketObserver = new CrimsonBlazorDecoderObserver();
        this.api = new CrimsonBlazorDecoderAPI(this);

        extensionHook.addApiImplementor(api);

        // Register observer with WebSocket extension early
        registerWebSocketObserver();

        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getBlazerPanel());
        }

        LOGGER.info("Crimson Blazor Decoder extension hooked successfully");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (extensionWebSocket != null && webSocketObserver != null) {
            extensionWebSocket.removeAllChannelObserver(webSocketObserver);
            LOGGER.info("Crimson Blazor Decoder WebSocket observer removed");
        }
        decoder = null;
        blazerPanel = null;
        webSocketObserver = null;
    }

    @Override
    public String getAuthor() {
        return "Renico Koen / crimsonwall.com";
    }

    @Override
    public String getDescription() {
        return getMessages().getString(PREFIX + ".desc");
    }

    @Override
    public URL getURL() {
        try {
            return URI.create("https://github.com/crimsonwall/crimsonblazordecoder").toURL();
        } catch (Exception e) {
            return null;
        }
    }

    /** Register the WebSocket observer with the WebSocket extension. */
    private void registerWebSocketObserver() {
        ExtensionWebSocket ws =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionWebSocket.class);
        if (ws != null) {
            extensionWebSocket = ws;
            extensionWebSocket.addAllChannelObserver(webSocketObserver);
            LOGGER.info("Crimson Blazor Decoder WebSocket observer registered");
        } else {
            LOGGER.warn("WebSocket extension not found - Crimson Blazor Decoder will not function");
        }
    }

    /** Get the main UI panel for displaying decoded Blazor messages. */
    public CrimsonBlazorDecoderPanel getBlazerPanel() {
        if (blazerPanel == null) {
            blazerPanel = new CrimsonBlazorDecoderPanel(this);
        }
        return blazerPanel;
    }

    /** Get the decoder instance. */
    public BlazorPackDecoder getDecoder() {
        return decoder;
    }

    /** Add a decoded Blazor Pack message to the UI panel. */
    public void addDecodedMessage(BlazorPackMessage message) {
        if (View.isInitialised() && blazerPanel != null) {
            EventQueue.invokeLater(
                    () -> {
                        blazerPanel.addMessage(message);
                    });
        }
    }

    /** Get the add-on's icon. */
    public static ImageIcon getIcon() {
        return new ImageIcon(
                DisplayUtils.getScaledIcon(
                                ExtensionCrimsonBlazorDecoder.class.getResource(
                                        "/resources/crimsonblazordecoder-icon.png"))
                        .getImage());
    }

    /**
     * WebSocket observer that intercepts and decodes Blazor Pack messages.
     *
     * <p>Registered with the ZAP WebSocket extension to receive all WebSocket message frames.
     * Filters for Blazor/SignalR messages, decodes them, and passes the result to the UI panel.
     */
    private class CrimsonBlazorDecoderObserver implements WebSocketObserver {

        @Override
        public int getObservingOrder() {
            return OBSERVER_ORDER;
        }

        @Override
        public boolean onMessageFrame(int channelId, WebSocketMessage message) {
            if (!message.isFinished()) {
                // Only process complete messages
                return true;
            }

            int opcode = message.getOpcode();
            if (opcode != WebSocketMessage.OPCODE_TEXT
                    && opcode != WebSocketMessage.OPCODE_BINARY) {
                // Only process text and binary frames
                return true;
            }

            try {
                byte[] payloadBytes = message.getPayload();

                if (payloadBytes == null || payloadBytes.length == 0) {
                    return true;
                }

                if (payloadBytes.length > MAX_PAYLOAD_SIZE) {
                    LOGGER.debug("Payload too large to process: {} bytes", payloadBytes.length);
                    return true;
                }

                // Log for debugging
                String preview =
                        new String(
                                payloadBytes,
                                0,
                                Math.min(100, payloadBytes.length),
                                java.nio.charset.StandardCharsets.UTF_8);
                LOGGER.debug(
                        "WebSocket message on channel {}: opcode={}, payloadLength={}, preview={}",
                        channelId,
                        opcode,
                        payloadBytes.length,
                        preview);

                // Check if this looks like a Blazor/SignalR message
                boolean isTextFrame = opcode == WebSocketMessage.OPCODE_TEXT;
                boolean isPotentialBlazorMessage =
                        isPotentialBlazorMessage(preview, isTextFrame, payloadBytes);

                if (!isPotentialBlazorMessage) {
                    LOGGER.debug("Message does not appear to be a Blazor message");
                    return true;
                }

                // Try to decode
                BlazorPackMessage blazorMessage = decoder.decode(payloadBytes, isTextFrame);
                if (blazorMessage != null) {
                    blazorMessage.setMessageId(channelId);
                    blazorMessage.setBinary(!isTextFrame);
                    blazorMessage.setOutgoing(
                            message.getDirection() == WebSocketMessage.Direction.OUTGOING);
                    LOGGER.info(
                            "Decoded Blazor message: type={}, channel={}",
                            blazorMessage.getMessageType(),
                            channelId);
                    addDecodedMessage(blazorMessage);
                } else {
                    LOGGER.debug("Failed to decode message as Blazor Pack");
                }

            } catch (Exception e) {
                LOGGER.error("Error processing WebSocket message for Blazor Pack", e);
            }

            return true;
        }

        @Override
        public void onStateChange(
                org.zaproxy.zap.extension.websocket.WebSocketProxy.State state,
                org.zaproxy.zap.extension.websocket.WebSocketProxy proxy) {
            // Log state changes for debugging
            LOGGER.debug("WebSocket state changed: {}, channel: {}", state, proxy.getChannelId());
        }

        /**
         * Quick heuristic to determine if a message might be a Blazor Pack message.
         *
         * @param payload The message payload as string preview
         * @param isTextFrame Whether this is a text frame
         * @param rawBytes The raw payload bytes
         * @return true if this might be a Blazor message
         */
        private boolean isPotentialBlazorMessage(
                String payload, boolean isTextFrame, byte[] rawBytes) {
            if (payload == null || payload.isEmpty()) {
                return false;
            }

            // For text frames, check for SignalR/Blazor markers
            if (isTextFrame) {
                return payload.contains("\"type\"")
                        || payload.contains("invocation")
                        || payload.contains("renderBatch")
                        || payload.contains("\"Close\"")
                        || payload.contains("\"Ping\"")
                        || payload.contains("blazor")
                        || payload.contains("Microsoft.AspNetCore")
                        || payload.contains("arguments")
                        || payload.contains("target")
                        || payload.contains("Invocation");
            }

            // For binary frames, check for valid MessagePack or SignalR binary markers.
            // SignalR binary messages start with 0x01 or 0x02.
            // Blazor Pack MessagePack messages typically start with fixarray (0x90-0x9f) or
            // fixmap (0x80-0x8f), sometimes preceded by a positive fixint prefix (0x00-0x7f)
            // or a BIN8/16/32 marker (0xc4-0xc6).
            if (rawBytes != null && rawBytes.length > 0) {
                int firstByte = rawBytes[0] & 0xFF;
                // SignalR binary format markers
                if (firstByte == 0x01 || firstByte == 0x02) {
                    return true;
                }
                // fixarray (0x90-0x9f) — common for SignalR hub messages
                if (firstByte >= 0x90 && firstByte <= 0x9f) {
                    return true;
                }
                // fixmap (0x80-0x8f)
                if (firstByte >= 0x80 && firstByte <= 0x8f) {
                    return true;
                }
                // BIN8/16/32 (0xc4-0xc6) — Blazor Pack multi-value encoding
                if (firstByte >= 0xc4 && firstByte <= 0xc6) {
                    return true;
                }
                // nil (0xc0) or FIXEXT (0xd4-0xd8) — extension markers
                if (firstByte == 0xc0 || (firstByte >= 0xd4 && firstByte <= 0xd8)) {
                    return true;
                }
                // Positive fixint (0x00-0x7f) as BlazorPack prefix — only if followed by
                // a valid MessagePack type
                if (firstByte <= 0x7f && rawBytes.length > 1) {
                    int secondByte = rawBytes[1] & 0xFF;
                    if ((secondByte >= 0x90 && secondByte <= 0x9f) // fixarray
                            || (secondByte >= 0x80 && secondByte <= 0x8f) // fixmap
                            || secondByte >= 0xc0) { // other MessagePack formats
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
