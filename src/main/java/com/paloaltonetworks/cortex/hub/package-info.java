/**
 * Collection of <code>Credentials</code> objects to be used alongside applications
 * leveraging the Cortex Data Lake API <a href="https://github.com/xhoms/pan-cortex-data-lake-java">https://github.com/xhoms/pan-cortex-data-lake-java</a>
 * <p>
 * It also provides the <code>HubHelper</code> class for quick prototyping SaaS
 * Components to interface with Cortex hub.
 * <h2>Credentials collection</h2> Quick overview of available classes
 * <h3>StaticCredentials</h3> The most basic of them all. It just wraps a static
 * <code>access_token</code> value <br>
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.Constants;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsStatic;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String ACCESS_TOKEN = "eyJh....65wg";
 *     final static String SQL_CMD = "SELECT * from `&lt;instance-id&gt;.firewall.traffic` LIMIT 20";
 * 
 *     public static void main(String[] args) throws HubException, KeyManagementException, NoSuchAlgorithmException {
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = new HubCredentialsStatic(Constants.USFQDN, ACCESS_TOKEN);
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable("SQL_CMD"))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * 
 * <h3>SimpleCredentialsProvider</h3> A credentials object that provides a
 * refreshed `access_token` from a known OAuth2 `refresh_token` (plus
 * `client_id` and `client_secret`)
 * <p>
 * Best practise to keep secrets secure is to provide them using environmental
 * variables.
 * <p>
 * Bash code
 * 
 * <pre>
 * PAN_CLIENT_ID=&lt;client_id&gt; \ 
 * PAN_CLIENT_SECRET=&lt;client_secret&gt; \ 
 * PAN_REFRESH_TOKEN=&lt;refresh_token&gt; \ 
 * java Example.java
 * </pre>
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.HubCredentialProviderSimple;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String SQL_CMD = "SELECT * from `6955470833100799268.firewall.traffic` LIMIT 20";
 * 
 *     public static void main(String[] args)
 *             throws InterruptedException, HubException, KeyManagementException, NoSuchAlgorithmException {
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = HubCredentialProviderSimple.factory();
 *         System.out.println(cred.apply(true));
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * <p>
 * But, if needed, you can provide the secrets programatically.
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.HubCredentialProviderSimple;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String SQL_CMD = "SELECT * from `&lt;tenant_id&gt;.firewall.traffic` LIMIT 20";
 *     final static String clientId = "&lt;client_id&gt;";
 *     final static String clientSecret = "&lt;client_secret&gt;";
 *     final static String refreshToken = "&lt;refresh_token&gt;";
 * 
 *     public static void main(String[] args)
 *             throws InterruptedException, HubException, KeyManagementException, NoSuchAlgorithmException {
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = HubCredentialProviderSimple.factory(clientId,
 *                 clientSecret, refreshToken, null);
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * 
 * <h3>DevTokenCredentials</h3> Leverages a Token Redemption service (i.e. API
 * Explorer)
 * <p>
 * Best practise is to provide the developer token using an environmental
 * variable:
 * 
 * <pre>
 * PAN_DEVELOPER_TOKEN=&lt;developer_token&gt; \ 
 * PAN_DEVELOPER_TOKEN_PROVIDER=&lt;developer_token_provider_url&gt; \ 
 * PAN_ENTRYPOINT=&lt;cortex_region_fqdn&gt; \ 
 * java Example.java
 * </pre>
 * <p>
 * JAVA Example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsDevToken;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String SQL_CMD = "SELECT * from `&lt;instance_id&gt;.firewall.traffic` LIMIT 20";
 * 
 *     public static void main(String[] args) throws HubException, KeyManagementException, NoSuchAlgorithmException {
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = HubCredentialsDevToken.factory();
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * <p>
 * You can pass the developer token programatically if needed
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.Constants;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsDevToken;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String DEVELOPER_TOKEN = "eyJ0....YBBw";
 *     final static String DEVELOPER_TOKEN_PROVIDER = "https://app.apiexplorer.rocks/request_token";
 *     final static String SQL_CMD = "SELECT * from `&lt;instance_id&gt;.firewall.traffic` LIMIT 20";
 * 
 *     public static void main(String[] args) throws HubException, KeyManagementException, NoSuchAlgorithmException {
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = new HubCredentialsDevToken(Constants.USFQDN,
 *                 DEVELOPER_TOKEN, DEVELOPER_TOKEN_PROVIDER, null, null);
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * 
 * <h2>Credential Providers</h2> If your application grows to the point it needs
 * to interface with multiple data lake instances then you'll face the need to
 * store multiple `refresh_token`'s.
 * <p>
 * This is the moment when you can leverage the `HubCredentialProvider` abstract
 * class. This class provides methods to cover the full life-cycle of a OAuth2
 * secret:
 * <ul>
 * <li><code>addWithRefreshToken()</code>: To register a new data lake
 * instance</li>
 * <li><code>addWithCode()</code>: To register a new data lake instance using
 * the OAuth2 code (from the code grant flow)</li>
 * <li><code>revokeDatalake()</code>: To revoke already issued refresh
 * token</li>
 * <li><code>getCredentialsObject(datalakeId)</code>: Retrieves a
 * <code>Credentials</code> object bound to the data lake identifier.
 * </ul>
 * <p>
 * <code>HubCredentialProvider</code> is meant to be subclassed. Developer doing so must implement the following storage methods
 * that will be triggered when needed.
 * <ul>
 * <li><code>upsertStoreItem(dlid, item)</code>: to store <code>item</code> as
 * the valuer for data lake instance <code>dlid</code>
 * <li><code>deleteStoreItem(dlid)</code>: remove the item for the data lake
 * instance <code>dlid</code>
 * <li><code>getStoreItem(dlid)</code>: retrieve the item for the data lake
 * instance <code>dlid</code>
 * <li><code>loadDb()</code>: perform initial database load
 * </ul>
 * <p>
 * Subclass must call <code>super(opts)</code> with an object with configuration
 * options. The only two mandatory options are:
 * <ul>
 * <li><code>clientId</code>: OAuth2 application client_id value
 * <li><code>clientSecret</code>: OAuth2 application client_secret value
 * </ul>
 * <h3>FsCredProvider</h3> The library provides a
 * <code>HubCredentialProvider</code> implementation that stores the secrets in
 * a local file using AES encryption of sensitive values. You can leverage this
 * class for initial prototyping.
 * <p>
 * Secrets must me provided as environmental variables:
 * <p>
 * bash code
 * 
 * <pre>
 * PAN_CLIENT_ID=&lt;OAuth2 client_id&gt; \ 
 * PAN_CLIENT_SECRET=&lt;OAuth2 client_secret&gt; \ 
 * PAN_SECRET=&lt;AES Encryption key&gt; \ 
 * java Example.java
 * </pre>
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * 
 * import com.paloaltonetworks.cortex.hub.HubCredentialProvider;
 * import com.paloaltonetworks.cortex.hub.HubCredentialProviderFS;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsMetadata;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * 
 * public class Example {
 *     public static void main(String[] args)
 *             throws InterruptedException, HubException, KeyManagementException, NoSuchAlgorithmException {
 *         HubCredentialProvider&lt;HubCredentialsMetadata&gt; credProv = HubCredentialProviderFS.factory();
 *     }
 * }
 * </pre>
 * <p>
 * Now you can register a <code>refresh_token</code> you've received (i.e. at the end of a
 * OAuth2 code grant flow)
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.HubCredentialProvider;
 * import com.paloaltonetworks.cortex.hub.HubCredentialProviderFS;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsMetadata;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String SQL_CMD = "SELECT * from `&lt;tenant_id&gt;.firewall.traffic` LIMIT 20";
 *     final static String REFRESH_TOKEN = "&lt;refresh_token&gt;";
 * 
 *     public static void main(String[] args)
 *             throws InterruptedException, HubException, KeyManagementException, NoSuchAlgorithmException {
 *         HubCredentialProvider&lt;HubCredentialsMetadata&gt; credProv = HubCredentialProviderFS.factory();
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = credProv.addWithRefreshToken("datalake-id",
 *                 Constants.USFQDN, REFRESH_TOKEN, null, null, null);
 * 
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * <p>
 * Or, if you want, you can use the CredentialProvider object to complete the
 * OAuth2 code grant flow for you.
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.HubCredentialProvider;
 * import com.paloaltonetworks.cortex.hub.HubCredentialProviderFS;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsMetadata;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String SQL_CMD = "SELECT * from `&lt;tenant_id&gt;.firewall.traffic` LIMIT 20";
 *     final static String CODE = "&lt;OAuth2_code&gt;";
 *     final static String CALLBACK_URL = "https://&lt;my_fqdn&gt;/auth_callback";
 * 
 *     public static void main(String[] args)
 *             throws InterruptedException, HubException, KeyManagementException, NoSuchAlgorithmException {
 *         HubCredentialProvider&lt;HubCredentialsMetadata&gt; credProv = HubCredentialProviderFS.factory();
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = credProv.addWithCode("datalake-id", Constants.USFQDN,
 *                 CODE, CALLBACK_URL, null);
 * 
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * <p>
 * In any case you receive at the end of the process a valid
 * <code>Credentials</code> object bound to the provided OAuth2 instance.
 * <p>
 * Secrets keep stored in a file named <code>PANCLOUD_CONFIG.json</code> (you
 * can use another file name using the option <code>configFile</code> in the
 * static <code>factory()</code> method).
 * <p>
 * The static <code>factory()</code> methods attempts to locate the database
 * file and, if found, then its content is loaded as initial data. That means
 * that you retrieve a credentials object for a data lake instance that was
 * registered in another work session.
 * <p>
 * JAVA example
 * 
 * <pre>
 * import java.security.KeyManagementException;
 * import java.security.NoSuchAlgorithmException;
 * import java.util.Map;
 * import java.util.function.Function;
 * 
 * import com.paloaltonetworks.cortex.hub.HubCredentialProvider;
 * import com.paloaltonetworks.cortex.hub.HubCredentialProviderFS;
 * import com.paloaltonetworks.cortex.hub.HubCredentialsMetadata;
 * import com.paloaltonetworks.cortex.hub.HubException;
 * import com.paloaltonetworks.cortex.data_lake.QueryServiceClient;
 * 
 * public class Example {
 *     final static String SQL_CMD = "SELECT * from `&lt;instance_id&gt;.firewall.traffic` LIMIT 20";
 * 
 *     public static void main(String[] args)
 *             throws InterruptedException, HubException, KeyManagementException, NoSuchAlgorithmException {
 *         HubCredentialProvider&lt;HubCredentialsMetadata&gt; credProv = HubCredentialProviderFS.factory();
 *         Function&lt;Boolean, Map.Entry&lt;String, String&gt;&gt; cred = credProv.getCredentialsObject("datalake-id");
 * 
 *         var qsc = new QueryServiceClient(cred);
 *         for (var page : qsc.iterable(SQL_CMD))
 *             System.out.println(page.toString());
 *     }
 * }
 * </pre>
 * 
 * <h2>HubHelper</h2>
 * <code>HubHelper</code> is a class that provides two main features:
 * <ul>
 * <li>Hooks to help onboard customers that are consuming applications through
 * the Cortex hub
 * <ul>
 * <li>Initial <code>params</code> parsing</li>
 * <li>Generation of the IDP Authentication Request URL</li>
 * <li>Completing the OAuth2 code grant flow</li>
 * </ul>
 * </li>
 * <li>Multi-tenancy: It automates a <code>HubCredentialProvider</code>
 * leveraging its metadada capability to organize data lakes into tenants.</li>
 * </ul>
 * <p>
 * See code examples in the <code>/examples</code> folder
 */
package com.paloaltonetworks.cortex.hub;