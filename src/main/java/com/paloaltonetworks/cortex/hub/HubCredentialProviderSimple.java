/**
 * HubCredentialProviderSimple
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

import java.time.Duration;

/**
 * Memory-only implementation of the abstract class `CortexCredentialProvider`
 * to be used for quick starting Cortex API experiments with just one active
 * data lake. You only need to provide the OAuth2 application secret (client_id
 * and client_secret) as well as the refresh token value for the single data
 * lake to experiment with.
 * 
 * Use the static method `factory` to instantiate an object of this class.
 */
public class HubCredentialProviderSimple extends HubCredentialProvider<Object> {

    private HubCredentialProviderSimple(String clientId, String clientSecret, String tokenUrl, String revokeUrl,
            Integer retryAttempts, Integer retryDelay, Integer accessTokenGuard, Duration timeout, Boolean secure)
            throws HubException {
        super(clientId, clientSecret, tokenUrl, revokeUrl, retryAttempts, retryDelay, accessTokenGuard, timeout,
                secure);
    }

    /**
     * Instantiates a *memory-only* CredentialProvider subclass with only one data
     * lake manually registered. Obtains all configuration values either from
     * provided configuration options or from environmental variables.
     * 
     * @param clientId         OAUTH2 'client_id' value. If not provided will
     *                         attempt to get it from the 'PAN_CLIENT_ID'
     *                         environmental variable
     * @param clientSecret     OAUTH2 'client_secret' value. If not provided will
     *                         attempt to get it from the 'PAN_CLIENT_SECRET'
     *                         environmental variable
     * @param refreshToken     OAUTH2 'refresh_token' value. If not provided will
     *                         attempt to get it from the 'PAN_REFRESH_TOKEN'
     *                         environmental variable
     * @param entryPoint       Cortex Datalake regiona API entrypoint. If not
     *                         provided will attempt to get it from the
     *                         'PAN_ENTRYPOINT' environmental variable
     * @param datalakeId       Datalake Indentifier. Defaults to 'DEFAULT'
     * @param tokenUrl         (advanced users)
     * @param revokeUrl        (advanced users)
     * @param retryAttempts    Number of attempts to execute a give IDP operation
     *                         before giving up (null = 3)
     * @param retryDelay       Milliseconds to wait between attempts (null = 100)
     * @param accessTokenGuard Amount of seconds ahead of expirations that should
     *                         trigger a token refresh
     * @param timeout          Amounts of seconds before timming out any HTTP
     *                         operation (null = 10)
     * @param secure           If set to false then HTTPS certificate check will be
     *                         disabled (null = true)
     * @return a Credentials object bound to the provided 'refres_token'
     * @throws HubException         issues parsing responses
     * @throws InterruptedException communication issues fetching the initial access
     *                              token
     */
    public static HubCredentials factory(String clientId, String clientSecret, String refreshToken, String datalakeId,
            String entryPoint, String tokenUrl, String revokeUrl, Integer retryAttempts, Integer retryDelay,
            Integer accessTokenGuard, Duration timeout, Boolean secure) throws HubException, InterruptedException {
        HubCredentialProvider<Object> hcp = new HubCredentialProviderSimple(clientId, clientSecret, tokenUrl, revokeUrl,
                retryAttempts, retryDelay, accessTokenGuard, timeout, secure);
        String finalDatalakeId = (datalakeId == null) ? "DEFAULT_DATALAKE" : datalakeId;
        return hcp.addWithRefreshToken(finalDatalakeId,
                (entryPoint == null) ? Constants.USFQDN : entryPoint, refreshToken, null, null, null);
    }

    /**
     * Instantiates a *memory-only* CredentialProvider subclass with only one data
     * lake manually registered. Obtains all configuration values either from
     * provided configuration options or from environmental variables.
     * 
     * @param clientId     OAUTH2 'client_id' value. If not provided will attempt to
     *                     get it from the 'PAN_CLIENT_ID' environmental variable
     * @param clientSecret OAUTH2 'client_secret' value. If not provided will
     *                     attempt to get it from the 'PAN_CLIENT_SECRET'
     *                     environmental variable
     * @param refreshToken OAUTH2 'refresh_token' value. If not provided will
     *                     attempt to get it from the 'PAN_REFRESH_TOKEN'
     *                     environmental variable
     * @param entryPoint   Cortex Datalake regiona API entrypoint. If not provided
     *                     will attempt to get it from the 'PAN_ENTRYPOINT'
     *                     environmental variable
     * @return a Credentials object bound to the provided 'refres_token'
     * @throws HubException         issues parsing responses
     * @throws InterruptedException communication issues fetching the initial access
     *                              token
     */
    public static HubCredentials factory(String clientId, String clientSecret, String refreshToken, String entryPoint)
            throws HubException, InterruptedException {
        return factory(clientId, clientSecret, refreshToken, null, entryPoint, null, null, null, null, null, null,
                null);
    }

    /**
     * Instantiates a *memory-only* CredentialProvider subclass with only one data
     * lake manually registered. Obtains all configuration values from environmental
     * variables.
     * 
     * @return a Credentials object bound to the provided 'refres_token'
     * @throws HubException         issues parsing responses
     * @throws InterruptedException communication issues fetching the initial access
     *                              token
     */
    public static HubCredentials factory() throws HubException, InterruptedException {
        String clientId = System.getenv("PAN_CLIENT_ID");
        if (clientId == null)
            throw new HubException("Environment variable PAN_CLIENT_ID not found.");
        String clientSecret = System.getenv("PAN_CLIENT_SECRET");
        if (clientSecret == null)
            throw new HubException("Environment variable PAN_CLIENT_SECRET not found.");
        String refreshToken = System.getenv("PAN_REFRESH_TOKEN");
        if (refreshToken == null)
            throw new HubException("Environment variable PAN_REFRESH_TOKEN not found.");
        String entryPoint = System.getenv("PAN_ENTRYPOINT");
        if (entryPoint == null) {
            entryPoint = Constants.APIEPMAP.get("americas");
            logger.info("Environmental variable PAN_ENTRYPOINT not found. Defaulting to " + entryPoint);
        }
        String datalakeId = System.getenv("PAN_DATALAKE_ID");
        if (datalakeId == null) {
            datalakeId = "DEFAULT_DATALAKE";
            logger.info("Environmental variable DEFAULT_DATALAKE not found. Defaulting to " + datalakeId);
        }
        return HubCredentialProviderSimple.factory(clientId, clientSecret, refreshToken, datalakeId, entryPoint, null,
                null, null, null, null, null, null);
    }

    @Override
    protected void upsertStoreItem(String datalakeId, StoreItem<Object> item) {
        logger.info("Memory-only credential provider. Discarding operation");
    }

    @Override
    protected void deleteStoreItem(String datalakeId) {
        logger.info("Memory-only credential provider. Discarding operation");
    }

    @Override
    protected StoreItem<Object> getStoreItem(String datalakeId) {
        logger.info("Memory-only credential provider. Discarding operation");
        return null;
    }

    @Override
    void loadDb() {
    }
}