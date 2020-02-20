/**
 * HubCredentialsAuto
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

import java.util.logging.Logger;

/**
 * Utility class whose static 'getCredentials()' method attempts to instantiate
 * a valid 'HubCredentials' object from avaliable environmental variables.
 */
public class HubCredentialsAuto {
    private static Logger logger = Logger.getLogger("com.paloaltonetworks.cortex.hub");

    public static HubCredentials getCredentials() throws HubException {
        String clientId = System.getenv("PAN_CLIENT_ID");
        String clientSecret = System.getenv("PAN_CLIENT_SECRET");
        String refreshToken = System.getenv("PAN_REFRESH_TOKEN");
        String accessToken = System.getenv("PAN_ACCESS_TOKEN");
        String entryPoint = System.getenv("PAN_ENTRYPOINT");
        String datalakeId = System.getenv("PAN_DATALAKE_ID");

        if (entryPoint == null) {
            entryPoint = Constants.APIEPMAP.get("americas");
            logger.info("Environmental variable PAN_ENTRYPOINT not set. Assuming " + entryPoint);
        }

        if (!(accessToken != null || (clientId != null && clientSecret != null && refreshToken != null))) {
            logger.info(
                    "Neither 'PAN_ACCESS_TOKEN' (for static credentials) nor 'PAN_CLIENT_ID', 'PAN_CLIENT_SECRET' and 'PAN_REFRESH_TOKEN' for a memory-based credentials provider where provider. Will try with developer token credetials");
            try {
                return HubCredentialsDevToken.factory();
            } catch (Exception e) {
                throw new HubException(
                        "Failed to create a 'HubCredentialsDevToken' object and that was the last resort. ("
                                + e.getLocalizedMessage() + ")");
            }
        }

        if (clientId != null && clientSecret != null && refreshToken != null) {
            logger.info("Will try with a 'SimpleCredentialsProvider' object");

            try {
                return HubCredentialProviderSimple.factory(clientId, clientSecret, refreshToken, datalakeId, entryPoint,
                        null, null, null, null, null, null, null);
            } catch (Exception e) {
                throw new HubException(
                        "Failed to create a 'SimpleCredentialsProvider' object and that was the last resort. ("
                                + e.getLocalizedMessage() + ")");
            }
        }

        if (accessToken != null) {
            logger.info("Using startic credentials. No refresh available.");
            try {
                return new HubCredentialsStatic(accessToken, entryPoint);
            } catch (Exception e) {
                throw new HubException(
                        "Failed to create a 'HubCredentialsStatic' object and that was the last resort. ("
                                + e.getLocalizedMessage() + ")");
            }
        }
        throw new HubException("Unknown error attempting to instantiate a credentials object");
    }
}