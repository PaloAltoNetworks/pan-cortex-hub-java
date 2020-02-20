/**
 * HubClientParams
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

import java.net.URLDecoder;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue.ValueType;

/**
 * Describes the 'params' object provided by Cortex hub.
 */
public class HubClientParams {
    /**
     * Augmented 'region' property provided by Cortex hub. Use the 'paramsaParser'
     * method to generate this augmentation out of the BASE64 string provided by
     * Cortex hub
     */
    public static class CDLLocaltion {
        /**
         * Region value as provided by Cortex HUB
         */
        public final String region;
        /**
         * Augmented API entry point for the provided region
         */
        public final String entryPoint;

        protected CDLLocaltion(String region, String entryPoint) {
            this.region = region;
            this.entryPoint = entryPoint;
        }
    }

    /**
     * Unique ID assigned by Cortex HUB to this application-datalake combination
     */
    public final String instanceId;
    /**
     * Convenient placeholder to allow applications using this SDK attach a friendly
     * name to the Instance ID
     */
    public final String instanceName;
    /**
     * Augmented `region` property provided by Cortex HUB. Use the `paramsaParser`
     * method to generate this augmentation out of the BASE64 string provided by
     * Cortex HUB
     */
    public final CDLLocaltion location;
    /**
     * Serial number of the Cortex Datalake at the other end of this Instance ID
     */
    public final String lsn;
    /**
     * Optional fields requested in the application manifest file
     */
    public final Map<String, String> customFields;

    /**
     * Creates a new HubClientsParams object from values
     * 
     * @param instanceId   instance identifier
     * @param instanceName human-readable instance name
     * @param location     region and api entrypoint
     * @param lsn          Logging Service serial number
     * @param customFields Hub application Custom Fields
     */
    HubClientParams(String instanceId, String instanceName, CDLLocaltion location, String lsn,
            Map<String, String> customFields) {
        this.instanceId = instanceId;
        this.instanceName = instanceName;
        this.location = location;
        this.lsn = lsn;
        this.customFields = customFields;
    }

    /**
     * Creates a new HubClientsParams object from Cortex hub provided 'params'
     * 
     * @param params Cortex hub provided params
     * @return new HubClientsParams object
     * @throws HubException parsing issues
     */
    public static HubClientParams parse(String params) throws HubException {
        Map<String, String> customFields = null;
        String instanceId = null;
        String instanceName = null;
        String region = null;
        String lsn = null;
        String b64decParams;
        try {
            b64decParams = new String(Base64.getDecoder().decode(params));
        } catch (Exception e) {
            throw new HubException("Params is not a valid Base64 string");
        }
        for (String part : b64decParams.split("&")) {
            String[] kv = part.split("=");
            if (kv.length != 2)
                throw new HubException("Invalid key/value in params (" + part + ")");
            String key = null;
            String value = null;
            try {
                key = URLDecoder.decode(kv[0], "UTF-8");
                value = URLDecoder.decode(kv[1], "UTF-8");
            } catch (Exception e) {
                throw HubException.fromException(e);
            }
            switch (key) {
            case "instance_id":
                instanceId = value;
                break;
            case "instance_name":
                instanceName = value;
                break;
            case "region":
                region = value;
                break;
            case "lsn":
                lsn = value;
                break;
            default:
                if (customFields == null)
                    customFields = new HashMap<String, String>();
                customFields.put(key, value);
            }
        }
        if (instanceId == null || region == null)
            throw new HubException("Mandatory fields 'instance_id' and 'region' not provided in params.");
        if (!Constants.APIEPMAP.containsKey(region))
            throw new HubException("Unknown region (" + region + ")");
        return new HubClientParams(instanceId, instanceName, new CDLLocaltion(region, Constants.APIEPMAP.get(region)),
                lsn, customFields);
    }

    /**
     * Creates a new HubClientsParams object from JsonObject representation
     * 
     * @param object JSON representation
     * @return new HubClientsParams object
     * @throws HubException parsing issues
     */
    public static HubClientParams parse(JsonObject object) throws HubException {
        for (String key : new String[] { "instanceId", "instanceName", "region", "lsn" })
            if (!(object.containsKey(key) && object.get(key).getValueType() == ValueType.STRING)) {
                throw new HubException("Object does not contain mandatory string key " + key);
            }
        if (!(object.containsKey("customFields") && object.get("customFields").getValueType() == ValueType.OBJECT)) {
            throw new HubException("Object does not contain mandatory Object key customFields");
        }
        String instanceId = object.getString("instanceId");
        String instanceName = object.getString("instanceName");
        String region = object.getString("region");
        String lsn = object.getString("lsn");
        Map<String, String> customFields = new HashMap<String, String>();
        JsonObject cfields = object.getJsonObject("customFields");
        for (String key : cfields.keySet()) {
            if (cfields.get(key).getValueType() != ValueType.STRING)
                throw new HubException("Custom field key " + key + " is not of type String");
            customFields.put(key, cfields.getString(key));
        }
        if (!Constants.APIEPMAP.containsKey(region))
            throw new HubException("Unknown region (" + region + ")");
        return new HubClientParams(instanceId, instanceName, new CDLLocaltion(region, Constants.APIEPMAP.get(region)),
                lsn, customFields);
    }

    /**
     * Encodes this object into a JSON representation
     * 
     * @return JSON representation of this object
     */
    public JsonObject encode() {
        JsonObjectBuilder b = Json.createObjectBuilder().add("instanceId", instanceId);
        b.add("instanceName", instanceName);
        b.add("region", location.region);
        b.add("lsn", lsn);
        JsonObjectBuilder cFields = Json.createObjectBuilder();
        customFields.forEach(cFields::add);
        b.add("customFields", cFields.build());
        return b.build();
    }

}
