/**
 * HubCredentialProviderFS
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.logging.Level;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonValue;

public class HubCredentialProviderFS extends HubCredentialProvider<HubCredentialsMetadata> {
    private final SecretKeySpec key;
    private final IvParameterSpec iv;
    private final String configFile;

    private HubCredentialProviderFS(String clientId, String clientSecret, String tokenUrl, String revokeUrl,
            Integer retryAttempts, Integer retryDelay, Integer accessTokenGuard, Duration timeout, Boolean secure,
            String configFile, SecretKeySpec key, IvParameterSpec iv) throws HubException {
        super(clientId, clientSecret, tokenUrl, revokeUrl, retryAttempts, retryDelay, accessTokenGuard, timeout,
                secure);
        this.configFile = configFile;
        this.key = key;
        this.iv = iv;
    }

    /**
     * Implements the CortexCredentialProvider abstract class using a local file as
     * secret vault. Use the static method `factory` to instantiate and object of
     * this class.
     * 
     * @param clientId         OAUTH2 'client_id' value. If not provided will
     *                         attempt to get it from the 'PAN_CLIENT_ID'
     *                         environmental variable
     * @param clientSecret     OAUTH2 'client_secret' value. If not provided will
     *                         attempt to get it from the 'PAN_CLIENT_SECRET'
     *                         environmental variable
     * @param secret           Encryption key that will be used to store sensible
     *                         data at rest. If not provided will attempt to get it
     *                         from the 'PAN_SECRET' environmental variable.
     * @param configFile       Name of the file that will hosts the secrets database
     *                         (null = PANCLOUD_CONFIG.json)
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
     * @throws HubException Problems parsing data
     * @return an instantiated object from provided values
     */
    public static HubCredentialProviderFS factory(String clientId, String clientSecret, String secret,
            String configFile, String tokenUrl, String revokeUrl, Integer retryAttempts, Integer retryDelay,
            Integer accessTokenGuard, Duration timeout, Boolean secure) throws HubException {
        if (secret == null) {
            throw new HubException("Secret can't be set to null");
        }
        byte[] secretHash = Tools.shaone(secret);
        SecretKeySpec key = new SecretKeySpec(secretHash, 0, 16, "AES");
        IvParameterSpec iv = new IvParameterSpec(secretHash, 4, 16);
        String localConfigFile = (configFile == null) ? "PANCLOUD_CONFIG.json" : configFile;
        HubCredentialProviderFS credProv = new HubCredentialProviderFS(clientId, clientSecret, tokenUrl, revokeUrl,
                retryAttempts, retryDelay, accessTokenGuard, timeout, secure, localConfigFile, key, iv);
        credProv.loadDb();
        return credProv;
    }

    /**
     * Simplified factory method to instantiate a HubCredentialProviderFS from
     * environmental variables and default values.
     * 
     * @throws HubException Problems parsing data
     * @return an instantiated object from environmental variables
     */
    public static HubCredentialProviderFS factory() throws HubException {
        String clientId = System.getenv("PAN_CLIENT_ID");
        if (clientId == null)
            throw new HubException("Environment variable PAN_CLIENT_ID not found.");
        String clientSecret = System.getenv("PAN_CLIENT_SECRET");
        if (clientSecret == null)
            throw new HubException("Environment variable PAN_CLIENT_SECRET not found.");
        String secret = System.getenv("PAN_SECRET");
        if (secret == null)
            throw new HubException("Environment variable PAN_SECRET not found.");
        return HubCredentialProviderFS.factory(clientId, clientSecret, secret, null, null, null, null, null, null, null,
                null);
    }

    private HubCredentialsItem securize(HubCredentialsItem item) throws HubRuntimeException {
        return new HubCredentialsItem(encrypt(item.accessToken), item.validUntil, item.entryPoint,
                encrypt(item.refreshToken), item.datalakeId);
    }

    private HubCredentialsItem unSecurize(HubCredentialsItem item) throws HubRuntimeException {
        return new HubCredentialsItem(decrypt(item.accessToken), item.validUntil, item.entryPoint,
                decrypt(item.refreshToken), item.datalakeId);
    }

    private String encrypt(String text) throws HubRuntimeException {
        try {
            final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes()));
        } catch (Exception e) {
            throw HubRuntimeException.fromException(e);
        }
    }

    private String decrypt(String message) throws HubRuntimeException {
        try {
            final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return new String(cipher.doFinal(Base64.getDecoder().decode(message)));
        } catch (Exception e) {
            throw HubRuntimeException.fromException(e);
        }
    }

    @Override
    protected void upsertStoreItem(String datalakeId, StoreItem<HubCredentialsMetadata> item) {
        logger.info("Lazy implementation of upsert with a fullSync operation");
        fullSync();
    }

    @Override
    protected void deleteStoreItem(String datalakeId) {
        logger.info("Lazy implementation of upsert with a fullSync operation");
        fullSync();
    }

    @Override
    protected StoreItem<HubCredentialsMetadata> getStoreItem(String datalakeId) {
        return null;
    }

    private synchronized void fullSync() {
        try {
            FileOutputStream fo = new FileOutputStream(configFile, false);
            JsonObjectBuilder database = Json.createObjectBuilder();
            exportCredentials((dId, sItem) -> {
                JsonObjectBuilder b = Json.createObjectBuilder().add("secrets", securize(sItem.secrets).encode());
                if (sItem.metadata != null)
                    b.add("metadata", sItem.metadata.encode());
                database.add(dId, b.build());
            });
            fo.write(database.build().toString().getBytes());
            fo.close();
        } catch (Exception e) {
            logger.log(Level.WARNING, "Full-sync failed (" + e.getLocalizedMessage() + ")");
        }
    }

    @Override
    void loadDb() {
        JsonReader jr = null;
        HashMap<String, StoreItem<HubCredentialsMetadata>> newStore = new HashMap<String, StoreItem<HubCredentialsMetadata>>();
        try {
            jr = Json.createReader(new FileInputStream(configFile));
            JsonObject jo = jr.readObject();
            for (Entry<String, JsonValue> entry : jo.entrySet()) {
                JsonObject item = entry.getValue().asJsonObject();
                if (!item.containsKey("secrets"))
                    throw new HubException("'secrets' missing in entry");
                HubCredentialsItem hci = HubCredentialsItem.parse(item.getJsonObject("secrets"));
                HubCredentialsMetadata hcm = null;
                if (item.containsKey("metadata"))
                    hcm = HubCredentialsMetadata.parse(item.getJsonObject("metadata"));
                newStore.put(entry.getKey(), new StoreItem<HubCredentialsMetadata>(hcm, unSecurize(hci)));
            }
            jr.close();
        } catch (FileNotFoundException e) {
            logger.log(Level.SEVERE, "Unable to open configuration file for reading (" + configFile + ")");
        } catch (ClassCastException | HubException | JsonException e) {
            logger.log(Level.SEVERE, "Configuration file does not conform to the expected JSON schema");
            if (jr != null)
                jr.close();
        }
        store = newStore;
    }
}
