/**
 * HubIdpErrorResponse
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

import javax.json.JsonObject;
import javax.json.JsonStructure;

/**
 * Object representation of the Idp Error Response model
 */
class HubIdpErrorResponse {
    String error;
    String errorDescription;

    private HubIdpErrorResponse(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    static HubIdpErrorResponse parse(JsonStructure response) {
        String error = null;
        String errorDescription = null;
        try {
            JsonObject responseObject = response.asJsonObject();
            error = responseObject.getString("error");
            errorDescription = responseObject.getString("error_description");
            return new HubIdpErrorResponse(error, errorDescription);
        } catch (Exception e) {
            throw new HubRuntimeException("Unable to parse IDP Error Response");
        }
    }
}
