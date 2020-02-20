/**
 * HubRefreshResult
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
 * Represents an raw Cortex ID refresh response
 */
class HubRefreshResult {
    /**
     * JWT access_token value
     */
    String accessToken;
    /**
     * Unix timestamp (in seconds) that mark the expiration time for this
     * access_token
     */
    Long validUntil;

    HubRefreshResult(String accessToken, Long validUntil) {
        this.accessToken = accessToken;
        this.validUntil = validUntil;
    }
}
