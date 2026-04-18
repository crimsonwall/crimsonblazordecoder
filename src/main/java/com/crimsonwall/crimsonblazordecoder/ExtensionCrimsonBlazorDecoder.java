/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for OWASP ZAP.
 *
 * Written by Renico Koen / Crimson Wall (crimsonwall.com) in 2026.
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
package com.crimsonwall.crimsonblazordecoder;

import java.awt.EventQueue;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import com.crimsonwall.crimsonblazordecoder.decoder.BlazorPackDecoder;
import com.crimsonwall.crimsonblazordecoder.decoder.BlazorPackEncoder;
import com.crimsonwall.crimsonblazordecoder.decoder.BlazorPackMessage;
import com.crimsonwall.crimsonblazordecoder.decoder.DecoderUtils;
import com.crimsonwall.crimsonblazordecoder.regex.RegexConfig;
import com.crimsonwall.crimsonblazordecoder.regex.RegexEntry;
import com.crimsonwall.crimsonblazordecoder.regex.RegexStorage;
import com.crimsonwall.crimsonblazordecoder.ui.CrimsonBlazorDecoderPanel;
import com.crimsonwall.crimsonblazordecoder.ui.OptionsRegexPanel;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
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
    private static final int MAX_PAYLOAD_SIZE = DecoderUtils.MAX_PAYLOAD_SIZE;

    private volatile ExtensionWebSocket extensionWebSocket;
    private volatile BlazorPackDecoder decoder;
    private volatile CrimsonBlazorDecoderPanel blazerPanel;
    private volatile CrimsonBlazorDecoderObserver webSocketObserver;
    private volatile RegexStorage regexStorage;
    private volatile RegexConfig regexConfig;
    private volatile OptionsRegexPanel optionsPanel;

    /**
     * Active WebSocket proxies keyed by channel ID. Used to send modified packets back to the
     * server on behalf of the client.
     */
    private final Map<Integer, WebSocketProxy> activeProxies = new ConcurrentHashMap<>();

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
        this.regexStorage = new RegexStorage();

        // Load regex config on startup
        getRegexConfig().load();

        // Register observer with WebSocket extension early
        registerWebSocketObserver();

        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getBlazerPanel());
            // Register options panel in ZAP's Tools → Options dialog
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
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
        if (blazerPanel != null) {
            blazerPanel.cleanup();
        }
        if (extensionWebSocket != null && webSocketObserver != null) {
            extensionWebSocket.removeAllChannelObserver(webSocketObserver);
            LOGGER.info("Crimson Blazor Decoder WebSocket observer removed");
        }
        activeProxies.clear();
        decoder = null;
        blazerPanel = null;
        webSocketObserver = null;
        extensionWebSocket = null;
        regexStorage = null;
        regexConfig = null;
        optionsPanel = null;
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

    /** Check if a WebSocket channel is currently active (connected). */
    public boolean isChannelActive(int channelId) {
        return activeProxies.containsKey(channelId);
    }

    /** Get the decoder instance. */
    public BlazorPackDecoder getDecoder() {
        return decoder;
    }

    /** Get the regex configuration, lazy-initialised with synchronized access. */
    public synchronized RegexConfig getRegexConfig() {
        if (regexConfig == null) {
            regexConfig = new RegexConfig();
        }
        return regexConfig;
    }

    /** Get the options panel for regex settings, lazy-initialised with synchronized access. */
    public synchronized OptionsRegexPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new OptionsRegexPanel(this);
        }
        return optionsPanel;
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

    /**
     * Send a modified Blazor Pack packet to the server on the specified channel.
     *
     * <p>The {@code editedJson} is re-encoded as either a Blazor Pack binary packet or a text
     * SignalR message depending on {@code isBinary}. Only client-to-server (outgoing) traffic is
     * supported.
     *
     * @param channelId the WebSocket channel to send on
     * @param editedJson the JSON string representing the modified hub message
     * @param isBinary {@code true} to encode as a binary Blazor Pack packet; {@code false} for text
     * @throws IllegalArgumentException if {@code editedJson} cannot be parsed
     * @throws IOException if the underlying WebSocket send fails
     * @throws IllegalStateException if the channel is not currently active
     */
    public void sendModifiedPacket(int channelId, String editedJson, boolean isBinary)
            throws IOException {
        WebSocketProxy proxy = activeProxies.get(channelId);
        if (proxy == null) {
            throw new IllegalStateException(
                    "No active WebSocket connection found for channel " + channelId);
        }

        BlazorPackEncoder encoder = new BlazorPackEncoder();
        byte[] payload;
        int opcode;

        if (isBinary) {
            Object hubMessage = encoder.parseJson(editedJson);
            payload = encoder.encodeAsBlazerPack(hubMessage);
            opcode = WebSocketMessage.OPCODE_BINARY;
        } else {
            payload = encoder.encodeAsTextMessage(editedJson);
            opcode = WebSocketMessage.OPCODE_TEXT;
        }

        WebSocketChannelDTO channelDto = new WebSocketChannelDTO();
        channelDto.setId(channelId);

        WebSocketMessageDTO dto = new WebSocketMessageDTO(channelDto);
        dto.setPayload(payload);
        dto.setOpcode(opcode);
        dto.setOutgoing(true);
        dto.setPayloadLength(payload.length);

        proxy.sendAndNotify(dto, WebSocketProxy.Initiator.MANUAL_REQUEST);
        LOGGER.info(
                "Sent modified Blazor Pack packet on channel {}: {} bytes, binary={}",
                channelId,
                payload.length,
                isBinary);
    }

    /** Cached icon to avoid repeated loading. */
    private static volatile ImageIcon cachedIcon;

    /** Get the add-on's icon. */
    public static ImageIcon getIcon() {
        if (cachedIcon == null) {
            cachedIcon =
                    new ImageIcon(
                            DisplayUtils.getScaledIcon(
                                            ExtensionCrimsonBlazorDecoder.class.getResource(
                                                    "crimsonblazordecoder-icon.png"))
                                    .getImage());
        }
        return cachedIcon;
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

                String preview =
                        new String(
                                payloadBytes,
                                0,
                                Math.min(200, payloadBytes.length),
                                java.nio.charset.StandardCharsets.UTF_8);

                // Check if this looks like a Blazor/SignalR message
                boolean isTextFrame = opcode == WebSocketMessage.OPCODE_TEXT;
                boolean isPotentialBlazorMessage =
                        isPotentialBlazorMessage(preview, isTextFrame, payloadBytes);

                if (!isPotentialBlazorMessage) {
                    return true;
                }

                // Try to decode
                BlazorPackDecoder localDecoder = decoder;
                if (localDecoder == null) {
                    return true;
                }
                BlazorPackMessage blazorMessage = localDecoder.decode(payloadBytes, isTextFrame);
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
            LOGGER.debug("WebSocket state changed: {}, channel: {}", state, proxy.getChannelId());
            if (state == WebSocketProxy.State.OPEN) {
                activeProxies.put(proxy.getChannelId(), proxy);
            } else if (state == WebSocketProxy.State.CLOSED
                    || state == WebSocketProxy.State.CLOSING) {
                activeProxies.remove(proxy.getChannelId());
            }
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

            // For text frames, check for Blazor/SignalR-specific markers.
            // Generic JSON fields like "type" and "target" are excluded as they match
            // many non-Blazor protocols (e.g., JSON-RPC).
            if (isTextFrame) {
                return payload.contains("blazorpack")
                        || payload.contains("blazor")
                        || payload.contains("Blazor")
                        || payload.contains("renderBatch")
                        || payload.contains("RenderBatch")
                        || payload.contains("DispatchEvent")
                        || payload.contains("DotNet")
                        || payload.contains("Microsoft.AspNetCore")
                        || payload.contains("StartCircuit")
                        || payload.contains("EndInvokeJS")
                        || payload.contains("BeginInvokeDotNet")
                        || payload.contains("JS.")
                        || payload.contains("OnRenderCompleted")
                        || payload.contains("UpdateRootComponents")
                        || payload.contains("\"protocol\":")
                        || (payload.contains("\"type\":") && payload.contains("\"target\":"));
            }

            // For binary frames, accept frames that could be Blazor Pack messages.
            // Blazor Pack frames start with a VarInt length prefix followed by MessagePack data.
            // A valid single-byte VarInt (0x00-0x7f) gives the MessagePack payload length.
            // The next byte after the VarInt must be a valid MessagePack array start (fixarray 0x90-0x9f)
            // or a map start (0x80-0x8f), which is what SignalR hub messages use.
            if (rawBytes != null && rawBytes.length >= 3) {
                int firstByte = rawBytes[0] & 0xFF;
                if (firstByte <= 0x7f) {
                    // Single-byte VarInt — verify frame is long enough and next byte is MessagePack
                    if (rawBytes.length >= firstByte + 1) {
                        int msgPackStart = rawBytes[firstByte] & 0xFF;
                        // Check for fixarray (0x90-0x9f), array16 (0xdc), array32 (0xdd),
                        // fixmap (0x80-0x8f), map16 (0xde), map32 (0xdf)
                        if ((msgPackStart >= 0x90 && msgPackStart <= 0x9f)
                                || msgPackStart == 0xdc || msgPackStart == 0xdd
                                || (msgPackStart >= 0x80 && msgPackStart <= 0x8f)
                                || msgPackStart == 0xde || msgPackStart == 0xdf) {
                            return true;
                        }
                    }
                } else {
                    // Multi-byte VarInt (0x80-0xff) — accept only if the payload after VarInt
                    // starts with a MessagePack structure indicator
                    int varIntLen = 1;
                    while (varIntLen < rawBytes.length && (rawBytes[varIntLen - 1] & 0x80) != 0) {
                        varIntLen++;
                    }
                    if (varIntLen < rawBytes.length) {
                        int msgPackStart = rawBytes[varIntLen] & 0xFF;
                        if ((msgPackStart >= 0x90 && msgPackStart <= 0x9f)
                                || msgPackStart == 0xdc || msgPackStart == 0xdd
                                || (msgPackStart >= 0x80 && msgPackStart <= 0x8f)
                                || msgPackStart == 0xde || msgPackStart == 0xdf) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }

}
