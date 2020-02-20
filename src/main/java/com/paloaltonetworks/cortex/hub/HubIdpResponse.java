/**
 * HubIdpResponse
 * 
 * Copyright 2015-2020 Palo Alto Networks, Inc
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.paloaltonetworks.cortex.hub;

import java.util.Date;
import javax.json.JsonObject;
import javax.json.JsonStructure;

/**
 * Object representation of the Idp Response model
 */
class HubIdpResponse {
    String accessToken;
    String refreshToken;
    long validUntil;

    private HubIdpResponse(String accessToken, String refreshToken, long validUntil) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.validUntil = validUntil;
    }

    static HubIdpResponse parse(JsonStructure response) {
        String accessToken = null;
        String refreshToken = null;
        long validUntil = 0;
        try {
            JsonObject responseObject = response.asJsonObject();
            accessToken = responseObject.getString("access_token");
            if (responseObject.containsKey("refresh_token"))
                refreshToken = responseObject.getString("refresh_token");
            int expiresIn = Integer.valueOf(responseObject.getString("expires_in"));
            validUntil = new Date().getTime() / 1000 + expiresIn;
            return new HubIdpResponse(accessToken, refreshToken, validUntil);
        } catch (Exception e) {
            throw new HubRuntimeException("Unable to parse IDP Response");
        }
    }
}
