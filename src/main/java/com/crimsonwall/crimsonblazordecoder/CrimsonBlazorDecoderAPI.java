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

import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseSet;

/**
 * API for the Crimson Blazor Decoder add-on.
 *
 * <p>Provides programmatic access to Blazor Pack decoding functionality.
 */
public class CrimsonBlazorDecoderAPI extends ApiImplementor {

    private static final String PREFIX = "crimsonblazordecoder";

    private static final String ACTION_DECODE = "decode";

    private ExtensionCrimsonBlazorDecoder extension;

    /**
     * Creates the API endpoint bound to the given extension.
     *
     * @param extension the parent extension that owns this API
     */
    public CrimsonBlazorDecoderAPI(ExtensionCrimsonBlazorDecoder extension) {
        this.extension = extension;
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_DECODE:
                return handleDecode(name, params);
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    /**
     * Handles the {@code decode} API action.
     *
     * <p>Accepts a {@code payload} parameter (required) and an optional {@code binary} flag.
     * Returns the decoded message data as an API response set.
     *
     * @param actionName the name of the action being performed
     * @param params the API request parameters
     * @return the decoded message data
     * @throws ApiException if the payload is missing, invalid, or cannot be decoded
     */
    private ApiResponse handleDecode(String actionName, JSONObject params) throws ApiException {
        String payload = params.optString("payload", null);
        if (payload == null) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, "payload");
        }

        boolean isBinary = params.optBoolean("binary", false);
        byte[] payloadBytes;

        try {
            payloadBytes =
                    isBinary
                            ? java.util.Base64.getDecoder().decode(payload)
                            : payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, "payload");
        }

        com.crimsonwall.crimsonblazordecoder.decoder.BlazorPackMessage message =
                extension.getDecoder().decode(payloadBytes, !isBinary);

        if (message == null) {
            throw new ApiException(ApiException.Type.BAD_EXTERNAL_DATA);
        }

        return new ApiResponseSet<>(actionName, message.getDecodedData());
    }
}
