/**
 * HubHelper
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
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map.Entry;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.paloaltonetworks.cortex.hub.HubCredentialProvider.StoreItem;

/**
 * Class with methods to help interfacing with the Cortex hub.
 */
public class HubHelper {
    private String clientId;
    private String idpAuthUrl;
    protected HubCredentialProvider<HubCredentialsMetadata> credProvider;
    private String idpCallbackUrl;
    protected static Logger logger = Logger.getLogger("com.paloaltonetworks.cortex.hub");

    /**
     * Creates an instance from values
     * 
     * @param idpCallbackUrl One of the URI's provided in the `auth_redirect_uris`
     *                       field of the manifest file
     * @param credProv       a 'HubCredentialProvider' instance that will be used by
     *                       the 'authCallbackHandler' to register new datalakes
     *                       after activation
     * @param idpAuthUrl     IDP Authorization Request Entry Point (null =
     *                       https://identity.paloaltonetworks.com/as/authorization.oauth2)
     * @throws HubException parsing issues
     */
    public HubHelper(String idpCallbackUrl, HubCredentialProvider<HubCredentialsMetadata> credProv, String idpAuthUrl)
            throws HubException {
        if (idpCallbackUrl == null) {
            throw new HubException("'idpCallbackUrl' can't be null");
        }
        if (credProv == null) {
            throw new HubException("'credProv' can't be null");
        }
        this.idpCallbackUrl = idpCallbackUrl;
        this.credProvider = credProv;
        this.clientId = credProv.getClientId();
        this.idpAuthUrl = (idpAuthUrl == null) ? Constants.IDP_AUTH_URL : idpAuthUrl;
    }

    /**
     * Creates an instance with default values
     * 
     * @param idpCallbackUrl One of the URI's provided in the `auth_redirect_uris`
     *                       field of the manifest file
     * @param credProv       a 'HubCredentialProvider' instance that will be used by
     *                       the 'authCallbackHandler' to register new datalakes
     *                       after activation
     * @throws HubException parsing issues
     */
    public HubHelper(String idpCallbackUrl, HubCredentialProvider<HubCredentialsMetadata> credProv)
            throws HubException {
        this(idpCallbackUrl, credProv, null);
    }

    private static String map(String tenantId, String datalakeId) {
        String b64tId = Base64.getEncoder().encodeToString(tenantId.getBytes());
        return datalakeId + ":" + b64tId;
    }

    private static String unmap(String id) throws HubException {
        String[] parts = id.split(":");
        if (parts.length != 2)
            throw new HubException("unable to unmap " + id);
        return new String(Base64.getDecoder().decode(parts[1]));
    }

    private String stateEncode(String id, int seq) {
        return String.valueOf(seq) + "-" + id;
    }

    private static String stateDecode(String code) throws HubException {
        String[] parts = code.split("-");
        if (parts.length != 2)
            throw new HubException("unable to decode " + code);
        return parts[1];
    }

    /**
     * Prepares an IDP authorization request
     * 
     * @param tenantId   Requesting Tenant ID (will be store in the authorization
     *                   state)
     * @param datalakeId Datalake ID willing to activate (will be store in the
     *                   authorization state)
     * @param scope      OAUTH2 Data access Scope(s)
     * @return a URI ready to be consumed (typically to be used for a client 302
     *         redirect)
     * @throws HubException in case URI can't be build
     */
    public URI idpAuthRequest(String tenantId, String datalakeId, String[] scope) throws HubException {
        String id = map(tenantId, datalakeId);
        StoreItem<HubCredentialsMetadata> storeItem = credProvider.storeItem(id);
        HubCredentialsMetadata metadata = storeItem.metadata;
        String stateId = stateEncode(id, metadata.stateCode.size());
        List<String> pairs = new ArrayList<String>();
        pairs.add("response_type=code");
        try {
            pairs.add("client_id=" + URLEncoder.encode(clientId, "UTF-8"));
            pairs.add("redirect_uri=" + URLEncoder.encode(idpCallbackUrl, "UTF-8"));
            pairs.add("scope=" + URLEncoder.encode(String.join(" ", scope), "UTF-8"));
            pairs.add("instance_id=" + URLEncoder.encode(metadata.clientParams.instanceId, "UTF-8"));
            pairs.add("region=" + URLEncoder.encode(metadata.clientParams.location.region, "UTF-8"));
            pairs.add("state=" + URLEncoder.encode(stateId, "UTF-8"));
            String uri = idpAuthUrl + "?" + String.join("&", pairs);
            storeItem.metadata.stateCode.put(stateId, true);
            credProvider.storeItem(id, storeItem);
            logger.info("Providing IDP Auth URL (" + uri + ")");
            return new URI(uri);
        } catch (Exception e) {
            throw HubException.fromException(e);
        }
    }

    /**
     * Ready to consume handler to exchange the 'code' (OAuth2 code grant flow) for
     * its corresponding 'access_token' and 'refresh_token' and store them in the
     * safe storage
     * 
     * @param code     OAuth2 code value
     * @param state    OAuth2 state value
     * @param tenantId tenant to store the secrets into
     * @return the datalakeId (if successfull)
     * @throws HubException         Parsing errors
     * @throws InterruptedException Interruption while retrieving the OAuth2 secrets
     *                              (code grant flow)
     */
    public HubCredentials idpAuthCallback(String code, String state, String tenantId)
            throws HubException, InterruptedException {
        String id = stateDecode(state);
        String localTenantId = unmap(id);
        if (!localTenantId.equals(tenantId))
            throw new HubException("TenantID mismatch (" + tenantId + "/" + localTenantId + ")");
        StoreItem<HubCredentialsMetadata> storeItem = credProvider.storeItem(id);
        HubCredentialsMetadata metadata = storeItem.metadata;
        if (!metadata.stateCode.containsKey(state))
            throw new HubException("State Identifier not found (" + state + ")");
        metadata.stateCode.clear();
        return credProvider.addWithCode(id, metadata.clientParams.location.entryPoint, code, idpCallbackUrl, metadata);
    }

    /**
     * Parses Cortex hub provided params and registers the results in the store
     * 
     * @param params   Cortex hub provided params string
     * @param tenantId the tenant to store the params into
     * @return a CortexClientParams object
     * @throws HubException parsing issues
     */
    public HubClientParams hubParamsRegister(String params, String tenantId) throws HubException {
        HubClientParams hcp = HubClientParams.parse(params);
        String datalakeId = hcp.instanceId;
        String id = map(tenantId, datalakeId);
        StoreItem<HubCredentialsMetadata> sItem = new StoreItem<HubCredentialsMetadata>(
                new HubCredentialsMetadata(tenantId, datalakeId, hcp), null);
        credProvider.storeItem(id, sItem);
        return hcp;
    }

    /**
     * Retrieves the list of datalakes registered under this tenant
     * 
     * @param tenantId requesting Tenant ID
     * @return a List with Map.Entry elements. Entry key is the data lake identifier
     *         and value are its Cortex hub params
     */
    public List<Entry<String, HubClientParams>> listDatalake(String tenantId) {
        credProvider.loadDb();
        return credProvider.storeItem().stream().filter(x -> x.metadata != null && x.metadata.tenantId.equals(tenantId))
                .map(x -> new SimpleImmutableEntry<String, HubClientParams>(x.metadata.datalakeId,
                        x.metadata.clientParams))
                .collect(Collectors.toList());
    }

    /**
     * Retrieve the list of data lake id's that has been successfully authorized by
     * the user
     * 
     * @param tenantId requesting Tenant ID
     * @return a List with all data lake id's owned by the provided tenant
     *         identifier that contain secrets
     */
    public List<String> listActiveDatalake(String tenantId) {
        credProvider.loadDb();
        return credProvider.storeItem().stream()
                .filter(x -> x.secrets != null && x.metadata != null && x.metadata.tenantId.equals(tenantId))
                .map(x -> x.metadata.datalakeId).collect(Collectors.toList());
    }

    /**
     * Gets metadata of a given Datalake ID as a 'HubClientParams' object
     * 
     * @param tenantId   requesting Tenant ID
     * @param datalakeId ID of the Datalake
     * @return the reported Cortex hub params for this data lake
     */
    public HubClientParams getDatalake(String tenantId, String datalakeId) {
        var entries = listDatalake(tenantId);
        if (entries.size() == 0)
            return null;
        return entries.get(0).getValue();
    }

    /**
     * Deletes a datalake metadata record
     * 
     * @param tenantId   requesting Tenant ID
     * @param datalakeId ID of the datalake
     * @throws InterruptedException communication issues
     * @throws HubException         store issues
     */
    public void deleteDatalake(String tenantId, String datalakeId) throws InterruptedException, HubException {
        credProvider.deleteDatalake(map(tenantId, datalakeId));
    }

    /**
     * Get a credentials object for this tenant data lake combination
     * 
     * @param tenantId   tenant identifier
     * @param datalakeId data lake identifier
     * @return a 'Credentials' object valid for the provided identifiers
     * @throws HubException store issues
     */
    public HubCredentials getCredentialsObject(String tenantId, String datalakeId) throws HubException {
        String id = map(tenantId, datalakeId);
        StoreItem<HubCredentialsMetadata> sItem = credProvider.storeItem(id);
        if (sItem == null)
            throw new HubException("Datalake does not exist in the store (" + tenantId + "/" + datalakeId + ")");
        HubCredentialsItem secrets = sItem.secrets;
        if (secrets == null)
            throw new HubException("Datalake not yet authorized (" + tenantId + "/" + datalakeId + ")");
        return credProvider.getCredentialsObject(id);
    }
}