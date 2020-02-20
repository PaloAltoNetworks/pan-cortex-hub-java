/**
 * HttpFetch
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

import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.Builder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest.BodyPublisher;
import java.time.Duration;
import java.util.function.Supplier;
import java.util.logging.Logger;
import javax.json.Json;
import javax.json.JsonStructure;
import javax.json.stream.JsonParsingException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Builds on top of {@link java.net.http.HttpClient} to implement a HTTP fetcher
 * for Cortex API endpoints.
 */
class HttpFetch {

    private final HttpClient client;
    private final Duration timeout;
    private static Logger logger = Logger.getLogger("com.paloaltonetworks.cortex.hub");
    private static final Duration DEFAULT_DURATION = Duration.ofSeconds(10);
    private final int retry;
    private final int delay;
    static final int DEFAULT_RETRIES = 3;
    static final int DEFAULT_DELAY = 100;

    /**
     * Creates a custom HTTP fetcher object
     * 
     * @param timeout  default timeout for all requests
     * @param unsecure set it to true if you want to ignore SSL certificate errors
     * @param retry    amount of times to attempt the same operation in case of
     *                 error. Use null for default value of 3
     * @param delay    amount of milliseconds to wait between failed attempts. Use
     *                 null for default value of 100
     * @throws NoSuchAlgorithmException underlying OS SSL support issues
     * @throws KeyManagementException   underlying OS SSL support issues
     */
    HttpFetch(Duration timeout, boolean unsecure, Integer retry, Integer delay)
            throws NoSuchAlgorithmException, KeyManagementException {
        this.timeout = (timeout == null) ? DEFAULT_DURATION : timeout;
        this.retry = (retry == null) ? DEFAULT_RETRIES : retry;
        this.delay = (delay == null) ? DEFAULT_DELAY : delay;
        SSLContext sslContext = SSLContext.getInstance("TLS");
        if (unsecure) {
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            } };
            sslContext.init(null, trustAllCerts, null);
        } else {
            sslContext.init(null, null, null);
        }
        client = HttpClient.newBuilder().version(Version.HTTP_1_1).sslContext(sslContext).build();
    }

    /**
     * Creates a HTTP fetcher with default timeout
     * 
     * @throws NoSuchAlgorithmException underlying OS SSL support issues
     * @throws KeyManagementException   underlying OS SSL support issues
     */
    HttpFetch() throws KeyManagementException, NoSuchAlgorithmException {
        this(null, false, null, null);
    }

    private CortexApiResult<JsonStructure> op(HttpRequest request) throws HubException {
        HttpResponse<String> response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.finer("HTTP response status code: " + response.statusCode());
            logger.finer("HTTP response body: " + response.body());
        } catch (Exception e) {
            throw new HubException("Error fetching from " + request.uri().toString());
        }
        try {
            JsonStructure jsobj = Json.createReader(new StringReader(response.body())).read();
            return new CortexApiResult<JsonStructure>(jsobj, response.statusCode());
        } catch (JsonParsingException e) {
            logger.info("CORTEX response is not a valid JSON object: " + response.body());
            return new CortexApiResult<JsonStructure>(null, response.statusCode());
        }
    }

    CortexApiResult<JsonStructure> get(URI uri) throws InterruptedException, HubException {
        HttpFetch.logger.fine(String.format("GET op to %s", uri.toString()));
        return op(HttpRequest.newBuilder(uri).GET().build());
    }

    CortexApiResult<JsonStructure> reget(URI uri) throws InterruptedException, HubException {
        return retrier(() -> {
            try {
                return get(uri);
            } catch (Exception e) {
                throw new HubRuntimeException(e.getLocalizedMessage());
            }
        });
    }

    CortexApiResult<JsonStructure> get(URI uri, String... headers) throws HubException, InterruptedException {
        HttpFetch.logger.fine(String.format("GET op to %s", uri.toString()));
        Builder reqBuilder = HttpRequest.newBuilder(uri).GET();
        if (timeout != null)
            reqBuilder.timeout(timeout);
        if (headers != null)
            reqBuilder.headers(headers);
        return op(reqBuilder.build());
    }

    CortexApiResult<JsonStructure> reget(URI uri, String... headers) throws InterruptedException, HubException {
        return retrier(() -> {
            try {
                return get(uri, headers);
            } catch (Exception e) {
                throw HubRuntimeException.fromException(e);
            }
        });
    }

    CortexApiResult<JsonStructure> delete(URI uri) throws HubException, InterruptedException {
        HttpFetch.logger.fine(String.format("DELETE op to %s", uri.toString()));
        return op(HttpRequest.newBuilder(uri).DELETE().build());
    }

    CortexApiResult<JsonStructure> redelete(URI uri) throws InterruptedException, HubException {
        return retrier(() -> {
            try {
                return delete(uri);
            } catch (Exception e) {
                throw HubRuntimeException.fromException(e);
            }
        });
    }

    CortexApiResult<JsonStructure> delete(URI uri, String... headers) throws HubException, InterruptedException {
        HttpFetch.logger.fine(String.format("DELETE op to %s", uri.toString()));
        Builder reqBuilder = HttpRequest.newBuilder(uri).DELETE();
        if (timeout != null)
            reqBuilder.timeout(timeout);
        if (headers != null)
            reqBuilder.headers(headers);
        return op(reqBuilder.build());
    }

    CortexApiResult<JsonStructure> redelete(URI uri, String... headers) throws InterruptedException, HubException {
        return retrier(() -> {
            try {
                return delete(uri, headers);
            } catch (Exception e) {
                throw HubRuntimeException.fromException(e);
            }
        });
    }

    CortexApiResult<JsonStructure> post(URI uri, BodyPublisher publisher) throws HubException, InterruptedException {
        HttpFetch.logger.fine(String.format("POST op to %s", uri.toString()));
        return op(HttpRequest.newBuilder(uri).POST(publisher).build());
    }

    CortexApiResult<JsonStructure> repost(URI uri, BodyPublisher publisher) throws InterruptedException, HubException {
        return retrier(() -> {
            try {
                return post(uri, publisher);
            } catch (Exception e) {
                throw HubRuntimeException.fromException(e);
            }
        });
    }

    CortexApiResult<JsonStructure> post(URI uri, BodyPublisher publisher, String... headers)
            throws HubException, InterruptedException {
        HttpFetch.logger.fine(String.format("POST op to %s", uri.toString()));
        Builder reqBuilder = HttpRequest.newBuilder(uri).POST(publisher);
        if (timeout != null)
            reqBuilder.timeout(timeout);
        if (headers != null)
            reqBuilder.headers(headers);
        return op(reqBuilder.build());
    }

    CortexApiResult<JsonStructure> repost(URI uri, BodyPublisher publisher, String... headers)
            throws InterruptedException, HubException {
        return retrier(() -> {
            try {
                return post(uri, publisher, headers);
            } catch (Exception e) {
                throw HubRuntimeException.fromException(e);
            }
        });
    }

    private CortexApiResult<JsonStructure> retrier(Supplier<CortexApiResult<JsonStructure>> op)
            throws InterruptedException, HubException {
        int attempts = retry;
        Exception lastAttemptException = null;
        CortexApiResult<JsonStructure> result = null;

        while (attempts > 0) {
            try {
                result = op.get();
                break;
            } catch (Exception e) {
                lastAttemptException = e;
                logger.info("operation attempt failed (" + String.valueOf(retry - attempts + 1) + " of "
                        + String.valueOf(retry) + ")");
                Thread.sleep(delay);
                attempts--;
            }
        }

        if (lastAttemptException != null) {
            HubException he = new HubException(
                    "Unable to complete operation after " + String.valueOf(retry) + " attempts.");
            he.setStackTrace(lastAttemptException.getStackTrace());
            throw he;
        }
        return result;
    }
}