/**
 * HubDebugger
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
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.AbstractMap.SimpleImmutableEntry;

/**
 * Convenience 'HubHelper' subclass for quick starting experiments with Cortex
 * hub. Use its static method 'factory' to instantiate an object for this class
 */
public class HubDebugger extends HubHelper {

    /**
     * Instantiates object from values
     * 
     * @param idpCallbackUrl OAuth2 IDP callback value
     * @param idpAuthUrl     Use a non-default IDP authentication URL
     * @param clientId       OAuth2 application client_id
     * @param clientSecret   OAuth2 application client_secret
     * @param tokenUrl       Use a non-default IDP Token URL
     * @param revokeUrl      Use a non-default IDP Revoke URL
     * @throws HubException problems with the store
     */
    public HubDebugger(String idpCallbackUrl, String idpAuthUrl, String clientId, String clientSecret, String tokenUrl,
            String revokeUrl) throws HubException {
        super(idpCallbackUrl, new HubCredentialProvider<HubCredentialsMetadata>(clientId, clientSecret, tokenUrl,
                revokeUrl, null, null, null, null, null) {

            @Override
            protected void upsertStoreItem(String datalakeId, StoreItem<HubCredentialsMetadata> item) {
                logger.info(String.format("override: upsertStoreItem(%s, [%s,%s])", datalakeId,
                        (item.metadata == null) ? "null" : item.metadata.encode().toString(),
                        (item.secrets == null) ? "null" : item.secrets.encode().toString()));
            }

            @Override
            protected void deleteStoreItem(String datalakeId) {
                logger.info(String.format("override: deleteStoreItem(%s)", datalakeId));
            }

            @Override
            protected StoreItem<HubCredentialsMetadata> getStoreItem(String datalakeId) {
                logger.info(String.format("override: getStoreItem(%s)", datalakeId));
                return null;
            }

            @Override
            void loadDb() {
                logger.info("override: loadDb()");
            }
        }, idpAuthUrl);
    }

    /**
     * Instantiates object using default values
     * 
     * @param idpCallbackUrl OAuth2 IDP callback value
     * @param clientId       OAuth2 application client_id
     * @param clientSecret   OAuth2 application client_secret
     * @throws HubException problems with the store
     */
    public HubDebugger(String idpCallbackUrl, String clientId, String clientSecret) throws HubException {
        this(idpCallbackUrl, null, clientId, clientSecret, null, null);
    }

    /**
     * Dumps the internal database into a String value
     * 
     * @return the dumped database
     */
    public String dumpDatabase() {
        List<Entry<String, String>> db = new ArrayList<>();
        credProvider.exportCredentials((id, item) -> {
            String metadata = "METADATA: " + ((item.metadata == null) ? "null" : item.metadata.encode().toString());
            String secrets = "SECRETS: " + ((item.secrets == null) ? "null" : item.secrets.encode().toString());
            db.add(new SimpleImmutableEntry<String, String>(id, metadata + "\n" + secrets));
        });
        String returnValue = "";
        for (Entry<String, String> item : db) {
            returnValue += "ID: " + item.getKey() + "\n" + item.getValue() + "\n___\n";
        }
        return returnValue;
    }
}