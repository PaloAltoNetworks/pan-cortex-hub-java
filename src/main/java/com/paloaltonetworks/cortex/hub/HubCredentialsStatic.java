/**
 * HubCredentialsStatic
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

/**
 * A Credentials implementation that just wraps a explicitly provided
 * access_token. Any refresh call will fail so it will last as long as the
 * provided access_token expiration date. Use the static method `factory` to
 * instantiate an object of this class
 */
public class HubCredentialsStatic extends HubCredentials {

    /**
     * Creates a HubCredentialsStatic object from static values
     * 
     * @param entryPoint  Cortex API GW fqdn to use (region)
     * @param accessToken JWT access_token value
     * @throws HubException parsing issues
     */
    public HubCredentialsStatic(String entryPoint, String accessToken) throws HubException {
        super(entryPoint, accessToken);
    }

    /**
     * Creates a HubCredentialsStatic object from environmental variables and
     * default values
     * 
     * @return a HubCredentialsStatic object
     * @throws HubException parsing issues
     */
    public static HubCredentialsStatic factory() throws HubException {
        String accessToken = System.getenv("PAN_ACCESS_TOKEN");
        if (accessToken == null)
            throw new HubException("Missing mandatory environmental variable 'PAN_ACCESS_TOKEN'");
        String entryPoint = System.getenv("PAN_ENTRYPOINT");
        if (entryPoint == null) {
            entryPoint = Constants.USFQDN;
            logger.info("Environmental variable PAN_ENTRYPOINT not set. Assuming " + entryPoint);
        }
        return new HubCredentialsStatic(entryPoint, accessToken);
    }

    @Override
    public String retrieveAccessToken(boolean force) {
        return null;
    }
}