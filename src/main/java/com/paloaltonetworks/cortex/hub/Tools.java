/**
 * Tools
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

import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonObject;

import static java.net.URLEncoder.encode;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;

class Tools {
    static String querify(Map<String, String> params) {
        ArrayList<String> paramList = new ArrayList<String>(params.size());
        params.forEach((k, v) -> {
            try {
                paramList.add(encode(k, "UTF-8") + "=" + encode(v, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e.getMessage());
            }
        });
        return String.join("&", paramList);
    }

    static long expTokenExtractor(String token) throws HubException {
        String[] parts = token.split("\\.");
        if (parts.length != 3)
            throw new HubException("Not a valid JWT token");

        long validUntil = 0;
        try {
            byte[] claim = Base64.getDecoder().decode(parts[1]);
            JsonObject claimObject = Json.createReader(new ByteArrayInputStream(claim)).readObject();
            validUntil = claimObject.getJsonNumber("exp").longValue();
        } catch (Exception e) {
            throw new HubException("Not a valid JWT token");
        }
        return validUntil;
    }

    static byte[] shaone(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(text.getBytes());
        } catch (Exception e) {
            return null;
        }
    }
}