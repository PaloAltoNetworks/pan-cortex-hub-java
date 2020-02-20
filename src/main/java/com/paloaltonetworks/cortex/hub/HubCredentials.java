/**
 * HubCredentials
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

import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReentrantLock;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.function.Function;
import java.util.logging.Logger;

/**
 * Base abstract Credentials class
 */
public abstract class HubCredentials implements Function<Boolean, Map.Entry<String, String>> {
    private final String entryPoint;
    private Map.Entry<String, String> currentToken = null;
    private final ReentrantLock locker = new ReentrantLock();
    protected static Logger logger = Logger.getLogger("com.paloaltonetworks.cortex.hub");

    /**
     * Base abstract Credentials class
     * 
     * @param entryPoint  Cortex API GW entry point (region)
     * @param accessToken Initial Access Token Value
     * @throws HubException Class configuration error
     */
    protected HubCredentials(String entryPoint, String accessToken) throws HubException {
        if (entryPoint == null)
            throw new HubException("Configuration error: entryPoint can't be null");
        this.entryPoint = entryPoint;
        if (accessToken != null) {
            currentToken = new SimpleImmutableEntry<String, String>(entryPoint, accessToken);
        }
    }

    /**
     * Base abstract Credentials class
     * 
     * @param entryPoint Cortex API GW entry point (region)
     * @throws HubException Class configuration error
     */
    protected HubCredentials(String entryPoint) throws HubException {
        this(entryPoint, null);
    }

    /**
     * Calls the retrieveAccessToken() abstract method and, if return value is not
     * null, then the local token entry is updated and returned.
     * 
     * @return null if the last provided entry is still valid
     */
    @Override
    public Entry<String, String> apply(Boolean force) {
        int lastCode = (currentToken == null) ? 0 : currentToken.hashCode();
        if (locker.tryLock()) {
            try {
                String newToken = retrieveAccessToken(currentToken == null);
                if (newToken != null) {
                    currentToken = new SimpleImmutableEntry<String, String>(entryPoint, newToken);
                }
            } finally {
                locker.unlock();
            }
        } else {
            locker.lock();
            locker.unlock();
        }
        if (force != null && force || currentToken != null && lastCode != currentToken.hashCode())
            return currentToken;
        return null;
    }

    /**
     * Subclasses must implement this method with the logic needed to get a
     * refreshed access_token
     * 
     * @param force to signal we want the access token even if it has not changed
     * @return the new access token (if refreshed) or the old one if force == true.
     *         It returns null to signal no need to change previous cached value.
     */
    protected abstract String retrieveAccessToken(boolean force);
}