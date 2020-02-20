/**
 * HubCredentialsDevToken
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
import java.util.Date;

import javax.json.JsonStructure;

/**
 * Credentials implementation that allows token refresh operations to be hosted
 * elesewhere (Centralized Token Redemption Service)
 */
public class HubCredentialsDevToken extends HubCredentials {
    private final String developerToken;
    private final URI developerTokenProvider;
    private int accTokenGuardTime;
    private long validUntil;
    private boolean unsecure = false;
    private static final int DEFAULT_GUARD_TIME = 300;

    /**
     * Creates a custom HubCredentialsDevToken
     * 
     * @param entryPoint       Cortex API Gateway fqdn (region)
     * @param guardTime        Amount of seconds ahead of expirations that should
     *                         trigger a token refresh
     * @param devToken         developer token
     * @param devTokenProvider developer token provider (i.e.
     *                         https://app.developers.paloaltonetworks.com/request_token)
     * @param unsecure         set it to false to disable server certificate check
     * @throws HubException in case privided guardTime is too high
     */
    public HubCredentialsDevToken(String entryPoint, String devToken, String devTokenProvider, Integer guardTime,
            Boolean unsecure) throws HubException {
        super(entryPoint);
        if (guardTime == null)
            accTokenGuardTime = 3300;
        else {
            if (guardTime <= 3300 && guardTime >= 0) {
                accTokenGuardTime = guardTime;
            } else {
                throw new HubException("guardTime must be between 0 and 3300");
            }
        }
        developerToken = devToken;
        developerTokenProvider = URI.create(devTokenProvider);
        this.unsecure = (unsecure == null) ? false : unsecure;
    }

    /**
     * Creates a HubCredentialsDevToken object using default Developer Token
     * Provider
     * 
     * @param devToken   developer token
     * @param entryPoint Cortex API Gateway fqdn (region)
     * @throws HubException parsing issues
     */
    public HubCredentialsDevToken(String entryPoint, String devToken) throws HubException {
        this(entryPoint, devToken, Constants.DEV_TOKEN_PROVIDER, DEFAULT_GUARD_TIME, false);
    }

    /**
     * Creates a HubCredentialsDevToken from environmental variables and default
     * values
     * 
     * @return HubCredentialsDevToken initializated object
     * @throws HubException parsing issues
     */
    public static HubCredentialsDevToken factory() throws HubException {
        String entryPoint = System.getenv("PAN_ENTRYPOINT");
        String devToken = System.getenv("PAN_DEVELOPER_TOKEN");
        String devTokenProvider = System.getenv("PAN_DEVELOPER_TOKEN_PROVIDER");

        if (devToken == null)
            throw new HubException("Environmental variable 'PAN_DEVELOPER_TOKEN' not found");

        if (entryPoint == null) {
            entryPoint = Constants.USFQDN;
            logger.info("Environmental variable PAN_ENTRYPOINT not set. Assuming " + entryPoint);
        }

        if (devTokenProvider == null) {
            logger.info("Environmental variable PAN_DEVELOPER_TOKEN_PROVIDER not set. Assuming "
                    + Constants.DEV_TOKEN_PROVIDER);
            devTokenProvider = Constants.DEV_TOKEN_PROVIDER;
        }
        return new HubCredentialsDevToken(entryPoint, devToken, devTokenProvider, DEFAULT_GUARD_TIME, false);
    }

    private String devTokenConsume() throws Exception {
        HttpFetch fecther = new HttpFetch(null, unsecure, null, null);
        String accessToken = null;
        CortexApiResult<JsonStructure> resp = fecther.repost(this.developerTokenProvider, BodyPublishers.ofString(""),
                "content-type", "application/json", "accept", "application/json", "authorization",
                "Bearer " + this.developerToken);
        if (resp.result == null) {
            throw new HubException("Invalid response (status code " + String.valueOf(resp.statusCode) + ")");
        }
        try {
            accessToken = resp.result.asJsonObject().getString("access_token");
        } catch (NullPointerException e) {
            throw new HubException("access_token key does not exists");
        }
        return accessToken;
    }

    @Override
    public String retrieveAccessToken(boolean force) {
        if (force || new Date().getTime() + accTokenGuardTime * 1000 > validUntil * 1000) {
            logger.info("Asking for a new access_token");
            try {
                String accessToken = devTokenConsume();
                if (accessToken == null)
                    return null;
                validUntil = Tools.expTokenExtractor(accessToken);
                return accessToken;
            } catch (Exception e) {
                HubCredentialsDevToken.logger.info("Error fetching developer token (" + e.getLocalizedMessage() + ")");
            }
        }
        return null;
    }
}