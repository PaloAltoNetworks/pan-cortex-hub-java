package micronaut;

import javax.inject.Inject;

import com.paloaltonetworks.cortex.hub.HubClientParams;
import com.paloaltonetworks.cortex.hub.HubException;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.QueryValue;
import io.reactivex.Single;

@Controller("/")
public class Controller {
    HHelper hh;
    private final static String TENANT_ID = "default_tenant";

    @Inject
    HelloController(HHelper hh) {
        this.hh = hh;
    }

    // End Point main route (Cortex hub params parser)
    @Get(produces = MediaType.TEXT_PLAIN)
    public Single<String> paramsRegister(@QueryValue("params") String params) {
        return Single.just(hh.setParams(params, TENANT_ID));
    }

    // End Point for authorization request redirect
    @Get(value = "auth-request/{tenantId}/{datalakeId}", produces = MediaType.TEXT_PLAIN)
    public Single<String> authRequest(@PathVariable String tenantId, @PathVariable String datalakeId) {
        return Single.just(hh.getAuthRequest(tenantId, datalakeId));
    }

    // End Point for authorization request callback
    @Get(value = "auth-callback", produces = MediaType.TEXT_PLAIN)
    public Single<String> authCallback(@QueryValue("code") String code, @QueryValue("state") String state) {
        return Single.just(hh.setAuthCallback(code, state, TENANT_ID));
    }

    // End Point to delete (and revoke) an existing authorization
    @Get(value = "delete/{tenantId}/{datalakeId}", produces = MediaType.TEXT_PLAIN)
    public Single<String> delete(@PathVariable String tenantId, @PathVariable String datalakeId) {
        return Single.just(hh.delete(tenantId, datalakeId));
    }

    // End Point compatible with Developer Token credentials
    @Get(value = "token/{tenantId}/{datalakeId}", produces = MediaType.TEXT_PLAIN)
    public Single<String> token(@PathVariable String tenantId, @PathVariable String datalakeId) {
        return Single.just(hh.getToken(tenantId, datalakeId));
    }
}