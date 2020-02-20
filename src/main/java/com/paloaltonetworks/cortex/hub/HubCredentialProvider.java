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

import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.logging.Logger;
import javax.json.Json;

/**
 * Base abstract CredentialProvider class
 */
public abstract class HubCredentialProvider<T> {
    /**
     * Data Lake storage item
     */
    public static class StoreItem<T> {
        /**
         * Optional metadata
         */
        public T metadata;
        /**
         * OAuth2 secrets and related data
         */
        public HubCredentialsItem secrets;

        public StoreItem(T metadata, HubCredentialsItem secrets) {
            this.metadata = metadata;
            this.secrets = secrets;
        }
    }

    private final String clientId;
    private final String clientSecret;
    private final URI idpTokenUrl;
    private final URI idpRevokeUrl;
    protected Map<String, StoreItem<T>> store = new HashMap<String, StoreItem<T>>();
    private final Lock locker = new ReentrantLock();
    private final int accTokenGuardTime;
    private final HttpFetch fetcher;
    protected static Logger logger = Logger.getLogger("com.paloaltonetworks.cortex.hub");
    public static final int ACCESS_GUARD = 300;
    public static final int DEFAULT_RETRIES = 3;
    public static final int DEFAULT_DELAY = 100;
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    /**
     * Creates a HubCredentialProvider object from provided values
     * 
     * @param clientId         OAuth2 client_id value
     * @param clientSecret     OAuth2 client_secret value
     * @param tokenUrl         IDP Token Operation Entry Point. Defaults to
     *                         'https://api.paloaltonetworks.com/api/oauth2/RequestToken'
     * @param revokeUrl        IDP Token Revoke Entry Point. Defaults to
     *                         'https://api.paloaltonetworks.com/api/oauth2/RevokeToken'
     * @param retryAttempts    How many attempts to contact IDP before giving up.
     *                         Defaults to '3'
     * @param retryDelay       How many milliseconds to wait between retry attempts.
     *                         Defauls to '100' milliseconds
     * @param accessTokenGuard ow soon to expiration before the access token is
     *                         automatically refreshed. Defaults to '300' (5
     *                         minutes)
     * @param timeout          Underlying HTTP fetch object default timeout for
     *                         operations. Defaults to 100ms.
     * @param secure           Set it to true if you want the underlying HTTP fetch
     *                         object to not throw on certificate errors. Defaults
     *                         to 'false'
     * @throws HubException Limitiations with the underlying OS SSL support
     */
    protected HubCredentialProvider(String clientId, String clientSecret, String tokenUrl, String revokeUrl,
            Integer retryAttempts, Integer retryDelay, Integer accessTokenGuard, Duration timeout, Boolean secure)
            throws HubException {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        idpTokenUrl = URI.create((tokenUrl == null) ? Constants.IDP_TOKEN_URL : tokenUrl);
        idpRevokeUrl = URI.create((revokeUrl == null) ? Constants.IDP_REVOKE_URL : revokeUrl);
        accTokenGuardTime = (accessTokenGuard == null) ? ACCESS_GUARD : accessTokenGuard;
        try {
            fetcher = new HttpFetch((timeout == null) ? DEFAULT_TIMEOUT : timeout, (secure == null) ? false : secure,
                    (retryAttempts == null) ? DEFAULT_RETRIES : retryAttempts,
                    (retryDelay == null) ? DEFAULT_DELAY : retryDelay);
        } catch (Exception e) {
            throw HubException.fromException(e);
        }
    }

    /**
     * Creates a HubCredentialProvider object from default values
     * 
     * @param clientId     OAuth2 client_id value
     * @param clientSecret OAuth2 client_secret value
     * @throws HubException Limitiations with the underlying OS SSL support
     */
    protected HubCredentialProvider(String clientId, String clientSecret) throws HubException {
        this(clientId, clientSecret, Constants.IDP_TOKEN_URL, Constants.IDP_REVOKE_URL, DEFAULT_RETRIES, DEFAULT_DELAY,
                ACCESS_GUARD, DEFAULT_TIMEOUT, false);
    }

    /**
     * Exposes the OAuth2 application client_id
     * 
     * @return this CredentialProvider class OAUTH2 `clientId`
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * Exposes the internal store.
     * 
     * @param dlid store item identifier
     * @return the store item for the provided identifier
     */
    public StoreItem<T> storeItem(String dlid) {
        lazyInitStoreItem(dlid);
        return store.get(dlid);
    }

    /**
     * Exposes the internal store. Replaces an existing item
     * 
     * @param dlid  store item identifier
     * @param value new data
     * @return the store item for the provided identifier
     */
    public StoreItem<T> storeItem(String dlid, StoreItem<T> value) {
        store.put(dlid, value);
        upsertStoreItem(dlid, value);
        return value;
    }

    /**
     * Exposes the internal store.
     * 
     * @return a collection with all items in the store
     */
    public Collection<StoreItem<T>> storeItem() {
        return store.values();
    }

    private void lazyInitStoreItem(String dlid) {
        if (!store.containsKey(dlid)) {
            StoreItem<T> value = getStoreItem(dlid);
            if (value != null) {
                store.put(dlid, value);
            }
        }
    }

    private HubIdpResponse idpRefresh(String body, String... headers) throws InterruptedException, HubException {
        var res = fetcher.repost(idpTokenUrl, BodyPublishers.ofString(body), headers);
        if (res.result == null)
            throw new HubException("IDP response is null");
        HubIdpErrorResponse resErr = null;
        try {
            resErr = HubIdpErrorResponse.parse(res.result);
        } catch (Exception e) {
        }
        if (resErr != null)
            throw new HubException("IDP Refresh error (" + resErr.error + ":" + resErr.errorDescription + ")");

        HubIdpResponse idpResponse;
        try {
            idpResponse = HubIdpResponse.parse(res.result);
        } catch (Exception e) {
            HubException he = new HubException("Unable to parse IDP response");
            he.setStackTrace(e.getStackTrace());
            throw he;
        }
        return idpResponse;
    }

    private void idpRevoke(String body, String... headers) throws InterruptedException, HubException {
        var res = fetcher.repost(idpRevokeUrl, BodyPublishers.ofString(body), headers);
        if (res.result == null)
            throw new HubException("IDP response is null");
        String success = null;
        try {
            success = res.result.asJsonObject().getString("issuccess");
            if (success == null)
                throw new Exception();
        } catch (Exception e) {
            HubException he = new HubException("Unable to parse IDP response");
            he.setStackTrace(e.getStackTrace());
            throw he;
        }
        if (!success.equals("true"))
            throw new HubException("IDP revoke operation failed");
    }

    private HubIdpResponse refreshAccessToken(String refreshToken) throws InterruptedException, HubException {
        String body = Json.createObjectBuilder().add("client_id", clientId).add("client_secret", clientSecret)
                .add("refresh_token", refreshToken).add("grant_type", "refresh_token").build().toString();
        String[] headers = { "content-type", "application/json", "accept", "application/json" };
        return idpRefresh(body, headers);
    }

    /**
     * Use to exchange an OAuth2 code for its corresponding secrets (OAuth2 code
     * grant flow)
     * 
     * @param code           OAuth2 code value
     * @param idpCallbackUrl OAuth2 callback value
     * @return The IDP response
     */
    private synchronized HubIdpResponse fetchToken(String code, String idpCallbackUrl)
            throws InterruptedException, HubException {
        String body = Json.createObjectBuilder().add("client_id", clientId).add("client_secret", clientSecret)
                .add("redirect_uri", idpCallbackUrl).add("code", code).add("grant_type", "authorization_code").build()
                .toString();
        String[] headers = { "content-type", "application/json", "accept", "application/json" };
        return idpRefresh(body, headers);
    }

    /**
     * Issues a new credentials object for a datalake you have static access to its
     * 'refresh token' value
     * 
     * @param datalakeId   ID for this datalake
     * @param entryPoint   Cortex Datalake regional entry point
     * @param refreshToken OAUTH2 'refresh_token' value
     * @param accessToken  Initial access token value. If null, the method will use
     *                     the refresh token to get a new access token
     * @param validUntil   Initial valid until value (Unix ts in seconds)
     * @param metadata     context data to be stored alongside the secrets
     * @return a HubCredentials object for the new registered data lake
     * @throws HubException         issues parsing respones
     * @throws InterruptedException http-level interruption
     */
    public synchronized HubCredentials addWithRefreshToken(String datalakeId, String entryPoint, String refreshToken,
            String accessToken, Long validUntil, T metadata) throws InterruptedException, HubException {
        String localAccessToken = accessToken;
        String localRefreshToken = refreshToken;
        Long localValidUntil = validUntil;
        if (localAccessToken == null) {
            HubIdpResponse idpResponse = refreshAccessToken(refreshToken);
            if (idpResponse.refreshToken != null) {
                localRefreshToken = idpResponse.refreshToken;
                logger.info(
                        "Received new Cortex Refresh Token for datalake ID " + datalakeId + " from Identity Provider");
            }
            localAccessToken = idpResponse.accessToken;
            localValidUntil = idpResponse.validUntil;
            logger.info("Retrieved Cortex Access Token for datalake ID " + datalakeId + " from Identity Provider");
        }
        HubCredentialsItem credItem = new HubCredentialsItem(localAccessToken, localValidUntil, entryPoint,
                localRefreshToken, datalakeId);
        lazyInitStoreItem(datalakeId);
        StoreItem<T> sItem = store.get(datalakeId);
        if (sItem == null) {
            sItem = new StoreItem<T>(metadata, credItem);
            store.put(datalakeId, sItem);
        } else {
            sItem.secrets = credItem;
        }
        upsertStoreItem(datalakeId, sItem);
        HubCredentials credObject = getCredentialsObject(datalakeId);
        logger.info("Issued new Credentials Object for datalake ID " + datalakeId);
        return credObject;
    }

    /**
     * Issues a new credentials object for a datalake you have to its OAuth2 code
     * value (OAuth2 code grant flow)
     * 
     * @param datalakeId     ID for this datalake
     * @param entryPoint     Cortex Datalake regional entry point
     * @param code           OAuth2 code (code grant flow)
     * @param idpCallbackUrl OAuth2 URL callback (code grant flow)
     * @param metadata       context data to be stored alongside the secrets
     * @return a HubCredentials object for the new registered data lake
     * @throws HubException         issues parsing respones
     * @throws InterruptedException http-level interruption
     */
    public synchronized HubCredentials addWithCode(String datalakeId, String entryPoint, String code,
            String idpCallbackUrl, T metadata) throws InterruptedException, HubException {
        HubIdpResponse idpResponse = fetchToken(code, idpCallbackUrl);
        if (idpResponse.refreshToken == null) {
            throw new HubException(
                    "IDP response for datalake " + datalakeId + " authorization does not contain refresh_token value");
        }
        String localAccessToken = idpResponse.accessToken;
        Long localValidUntil = idpResponse.validUntil;
        HubCredentialsItem credItem = new HubCredentialsItem(localAccessToken, localValidUntil, entryPoint,
                idpResponse.refreshToken, datalakeId);
        lazyInitStoreItem(datalakeId);
        StoreItem<T> sItem = store.get(datalakeId);
        if (sItem == null) {
            sItem = new StoreItem<T>(metadata, credItem);
            store.put(datalakeId, sItem);
        } else {
            sItem.secrets = credItem;
        }
        upsertStoreItem(datalakeId, sItem);
        HubCredentials credObject = getCredentialsObject(datalakeId);
        logger.info("Issued new Credentials Object for datalake ID " + datalakeId);
        return credObject;
    }

    /**
     * Main method used by a bound Credentials object. Returns the current
     * 'access_token' It auto-refreshes the 'access_token' if needed based on the
     * 'accTokenGuardTime' class configuration option
     * 
     * @param datalakeId ID of the datalake to obtain 'access_token' from
     * @param force      return the current 'access_token' value even if it has not
     *                   changed from lats request.
     * @return a new access token or null if requester can keep last cached entry
     * @throws HubException         issues parsing respones
     * @throws InterruptedException http-level interruption
     */
    private synchronized String getAccessToken(String datalakeId, Boolean force)
            throws HubException, InterruptedException {
        lazyInitStoreItem(datalakeId);
        if (!store.containsKey(datalakeId)) {
            throw new HubException("Datalake not found in the store (" + datalakeId + ")");
        }
        StoreItem<T> sItem = store.get(datalakeId);
        HubCredentialsItem credItem = sItem.secrets;
        int lastCode = (credItem.accessToken == null) ? 0 : credItem.accessToken.hashCode();
        if (new Date().getTime() + accTokenGuardTime * 1000 > credItem.validUntil * 1000) {
            if (locker.tryLock()) {
                try {
                    logger.info("Asking for a new access_token");
                    HubIdpResponse idpResponse = refreshAccessToken(credItem.refreshToken);
                    credItem.accessToken = idpResponse.accessToken;
                    credItem.validUntil = idpResponse.validUntil;
                    if (idpResponse.refreshToken != null) {
                        credItem.refreshToken = idpResponse.refreshToken;
                        logger.info("Received new Cortex Refresh Token");
                    }
                    upsertStoreItem(datalakeId, sItem);
                } finally {
                    locker.unlock();
                }
            } else {
                locker.lock();
                locker.unlock();
            }
        }
        if (force != null && force || lastCode != credItem.accessToken.hashCode())
            return credItem.accessToken;
        return null;
    }

    /**
     * Retrieves the Credentials object for a given datalake
     * 
     * @param datalakeId ID of the datalake the Credentials object should be bound
     *                   to
     * @return a HubCredentials object for the requested data lake
     * @throws HubException         issues parsing respones
     */
    public synchronized HubCredentials getCredentialsObject(String datalakeId) throws HubException {
        lazyInitStoreItem(datalakeId);
        StoreItem<T> sItem = store.get(datalakeId);
        if (sItem == null) {
            throw new HubException("Datalake not found in the store (" + datalakeId + ")");
        }
        HubCredentialsItem credItem = sItem.secrets;
        if (credItem == null) {
            throw new HubException("Secrets not found in the store (" + datalakeId
                    + "). Did you forget to register the refresh token?");
        }
        return new HubCredentials(credItem.entryPoint, credItem.accessToken) {

            @Override
            protected String retrieveAccessToken(boolean force) {
                try {
                    return getAccessToken(datalakeId, force);
                } catch (Exception e) {
                    logger.info("Issue getting the access token (" + e.getMessage() + ")");
                    return null;
                }
            }
        };
    }

    /**
     * Revokes the refresh token for a given data lake
     * 
     * @param datalakeId the data lake id subject of this operation
     * @throws InterruptedException http fetch operation interruption
     * @throws HubException         problems handling the operation
     */
    public synchronized void revokeDatalake(String datalakeId) throws InterruptedException, HubException {
        lazyInitStoreItem(datalakeId);
        StoreItem<T> sItem = store.get(datalakeId);
        if (sItem == null) {
            logger.info("Ignoring revoke operation. Datalake not found in the store (" + datalakeId + ")");
            return;
        }
        HubCredentialsItem credItem = sItem.secrets;
        if (credItem != null) {
            String body = Json.createObjectBuilder().add("client_id", clientId).add("client_secret", clientSecret)
                    .add("token", credItem.refreshToken).add("token_type_hint", "refresh_token").build().toString();
            String[] headers = { "content-type", "application/json", "accept", "application/json" };
            idpRevoke(body, headers);
            logger.info("Successfully revoked refresh token for datalake " + datalakeId);
        } else {
            logger.info("Ignoring revoke operation. Datalake not yet authorized (" + datalakeId + ")");
        }
        sItem.secrets = null;
        upsertStoreItem(datalakeId, sItem);
    }

    /**
     * Removes a datalake (revokes its OAUTH2 `refresh_token` as well)
     * 
     * @param datalakeId ID of the datalake to be removed
     * @throws InterruptedException http fetch operation interruption
     * @throws HubException         problems handling the operation
     */
    public synchronized void deleteDatalake(String datalakeId) throws InterruptedException, HubException {
        revokeDatalake(datalakeId);
        this.store.remove(datalakeId);
        logger.info("Deleting item from the store (" + datalakeId + ")");
        deleteStoreItem(datalakeId);
    }

    /**
     * Loops all credential items in the store and applies the exporter consumer
     * 
     * @param exporter consumer
     */
    protected synchronized void exportCredentials(BiConsumer<String, StoreItem<T>> exporter) {
        if (store != null)
            store.forEach(exporter);
    }

    /**
     * Implementation dependant. Must create or update the corresponfing item in the
     * store
     * 
     * @param datalakeId datalake identificator
     * @param item       element to be stored
     */
    protected abstract void upsertStoreItem(String datalakeId, StoreItem<T> item);

    /**
     * Implementation dependant. Must delete an item from the store
     * 
     * @param datalakeId datalake identificator
     */
    protected abstract void deleteStoreItem(String datalakeId);

    /**
     * Implementation dependant. Must return the store item
     * 
     * @param datalakeId datalake identificator
     * @return the corresponding item from the store
     */
    protected abstract StoreItem<T> getStoreItem(String datalakeId);

    /**
     * Implementation dependant. A way to trigger the external DB initial load must
     * be provided. The subclass implementation should compare the protected object
     * `store` with the external data and update it if needed.
     */
    abstract void loadDb();
}
