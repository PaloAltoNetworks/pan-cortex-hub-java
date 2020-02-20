/**
 * HubCredentialProvider
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

import java.util.HashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;

/**
 * Describes an object that keeps a Tenant Identifier
 */
public class HubCredentialsMetadata {
    final String tenantId;
    final String datalakeId;
    final Map<String, Boolean> stateCode;
    final HubClientParams clientParams;

    /**
     * Creates instance from values
     * 
     * @param tenantId     tenant identifier
     * @param datalakeId   data lake identifier
     * @param clientParams Cortex hub params object
     * @param stateCode    pre-existing authorization attempts code
     */
    public HubCredentialsMetadata(String tenantId, String datalakeId, HubClientParams clientParams,
            Map<String, Boolean> stateCode) {
        this.tenantId = tenantId;
        this.datalakeId = datalakeId;
        this.clientParams = clientParams;
        this.stateCode = stateCode;
    }

    /**
     * Creates instance from values
     * 
     * @param tenantId     tenant identifier
     * @param datalakeId   data lake identifier
     * @param clientParams Cortex hub params object
     */
    public HubCredentialsMetadata(String tenantId, String datalakeId, HubClientParams clientParams) {
        this(tenantId, datalakeId, clientParams, new HashMap<String, Boolean>());
    }

    /**
     * Factory method to create an instance from a JSON representation
     * 
     * @param metadata JSON representation
     * @return object instance
     * @throws HubException parsing errors
     */
    public static HubCredentialsMetadata parse(JsonObject metadata) throws HubException {
        if (!(metadata.containsKey("tenantId") && metadata.get("tenantId").getValueType() == ValueType.STRING)) {
            throw new HubException("Metadata does not contain mandatory string key 'tenantId'");
        }
        if (!(metadata.containsKey("datalakeId") && metadata.get("datalakeId").getValueType() == ValueType.STRING)) {
            throw new HubException("Metadata does not contain mandatory string key 'datalakeId'");
        }
        if (!(metadata.containsKey("clientParams")
                && metadata.get("clientParams").getValueType() == ValueType.OBJECT)) {
            throw new HubException("Metadata does not contain mandatory Object key 'clientParams'");
        }
        String tenantId = metadata.getString("tenantId");
        String datalakeId = metadata.getString("datalakeId");
        HubClientParams clientParams = HubClientParams.parse(metadata.getJsonObject("clientParams"));
        Map<String, Boolean> stateCode = new HashMap<String, Boolean>();
        if (metadata.containsKey("stateCode")) {
            if (metadata.get("stateCode").getValueType() != ValueType.ARRAY) {
                throw new HubException("Metadata Object key 'stateCode' is not an array");
            }
            for (JsonValue entry : metadata.getJsonArray("stateCode")) {
                if (entry.getValueType() != ValueType.STRING)
                    throw new HubException("Entry in 'stateCode' is not a String");
                stateCode.put(entry.toString(), true);

            }
        }
        return new HubCredentialsMetadata(tenantId, datalakeId, clientParams, stateCode);
    }

    /**
     * Encodes the object into a JsonObject instance
     * 
     * @return JsonObject
     */
    public JsonObject encode() {
        JsonObjectBuilder b = Json.createObjectBuilder();
        b.add("tenantId", tenantId);
        b.add("datalakeId", datalakeId);
        b.add("clientParams", clientParams.encode());
        JsonArrayBuilder a = Json.createArrayBuilder();
        stateCode.keySet().forEach(a::add);
        b.add("stateCode", a.build());
        return b.build();
    }
}