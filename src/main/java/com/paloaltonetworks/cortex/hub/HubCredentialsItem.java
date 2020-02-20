/**
 * HubCredentialsItem
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

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue.ValueType;

/**
 * Library Representation of a Cortex credential set
 */
public class HubCredentialsItem {
    /**
     * JWT access_token value
     */
    public String accessToken;
    /**
     * Unix timestamp (in seconds) that mark the expiration time for this
     * access_token
     */
    public long validUntil;
    /**
     * Cortex API fqdn (region) in which this access_token is valid
     */
    public String entryPoint;
    /**
     * refresh_token value bound to this access_token
     */
    public String refreshToken;
    /**
     * data lake identifier (application instance id)
     */
    public String datalakeId;

    /**
     * Instantiates object from values
     * 
     * @param accessToken  OAuth2 access_token value
     * @param validUntil   Unix TS expiration mark
     * @param entryPoint   Cortex API fqdn (region)
     * @param refreshToken OAuth2 refresh_token
     * @param datalakeId   Data Lake unique identifier
     */
    public HubCredentialsItem(String accessToken, long validUntil, String entryPoint, String refreshToken,
            String datalakeId) {
        this.accessToken = accessToken;
        this.validUntil = validUntil;
        this.entryPoint = entryPoint;
        this.refreshToken = refreshToken;
        this.datalakeId = datalakeId;
    }

    /**
     * Encodes instance as a JsonObject
     * 
     * @return a JSON version of the object
     */
    public JsonObject encode() {
        JsonObjectBuilder b = Json.createObjectBuilder();
        b.add("accessToken", accessToken);
        b.add("entryPoint", entryPoint);
        b.add("refreshToken", refreshToken);
        b.add("datalakeId", datalakeId);
        b.add("validUntil", validUntil);
        return b.build();
    }

    /**
     * Instantiates object from JSON representation
     * 
     * @param object JSON representation
     * @return Instantiated CredentialsItem object
     * @throws HubException parsing issues
     */
    public static HubCredentialsItem parse(JsonObject object) throws HubException {
        for (String key : new String[] { "entryPoint", "accessToken", "refreshToken", "datalakeId" }) {
            if (!(object.containsKey(key) && object.get(key).getValueType() == ValueType.STRING))
                throw new HubException("CredentialsItem does not contain mandatory string key '" + key + "'");
        }
        if (!(object.containsKey("validUntil") && object.get("validUntil").getValueType() == ValueType.NUMBER))
            throw new HubException("CredentialsItem does not contain mandatory number key 'validUntil'");
        String accessToken = object.getString("accessToken");
        String refreshToken = object.getString("refreshToken");
        String datalakeId = object.getString("datalakeId");
        String entryPoint = object.getString("entryPoint");
        Long validUntil = object.getJsonNumber("validUntil").longValue();
        return new HubCredentialsItem(accessToken, validUntil, entryPoint, refreshToken, datalakeId);
    }
}