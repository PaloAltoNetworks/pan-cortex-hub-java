package micronaut;

import java.util.Map.Entry;

import javax.inject.Singleton;
import com.paloaltonetworks.cortex.hub.HubHelper;
import com.paloaltonetworks.cortex.hub.HubDebugger;
import com.paloaltonetworks.cortex.hub.HubException;
import com.paloaltonetworks.cortex.hub.Constants;
import com.paloaltonetworks.cortex.hub.HubClientParams;
import com.paloaltonetworks.cortex.hub.HubCredentials;

@Singleton
class CortexHubBean {
    private static final String clientId = "<client_id>";
    private static final String clientSecret = "<client_secret>";
    private static final String idpCallbackUrl = "https://<app_fqdn>/auth_callback";
    private final HubDebugger hh;

    CortexHubBean() throws HubException {
        hh = new HubDebugger(idpCallbackUrl, clientId, clientSecret);
    }

    String setParams(String params, String tenantId) {
        try {
            String returnValue = hh.hubParamsRegister(params, tenantId).encode().toString();
            return returnValue + "\n___\n" + hh.dumpDatabase();
        } catch (HubException e) {
            return "error: " + e.getClass().getName() + ":" + e.getLocalizedMessage();
        }
    }

    String getAuthRequest(String tenantId, String datalakeId) {
        try {
            String returnValue = hh.idpAuthRequest(tenantId, datalakeId, new String[] { Constants.SCOPE_LS_READ })
                    .toString();
            return returnValue + "\n___\n" + hh.dumpDatabase();
        } catch (HubException e) {
            return "error: " + e.getClass().getName() + ":" + e.getLocalizedMessage();
        }
    }

    String setAuthCallback(String code, String state, String tenantId) {
        try {
            hh.idpAuthCallback(code, state, tenantId);
            return hh.dumpDatabase();
        } catch (HubException | InterruptedException e) {
            return "error: " + e.getClass().getName() + ":" + e.getLocalizedMessage();
        }
    }

    String delete(String tenantId, String datalakeId) {
        try {
            hh.deleteDatalake(tenantId, datalakeId);
            return hh.dumpDatabase();
        } catch (InterruptedException | HubException e) {
            return "error: " + e.getClass().getName() + ":" + e.getLocalizedMessage();
        }
    }

    String getToken(String tenantId, String datalakeId) {
        HubCredentials cred;
        try {
            cred = hh.getCredentialsObject(tenantId, datalakeId);
            return String.format("{\"access_token\":\"%s\"}", cred.apply(true).getValue());
        } catch (HubException e) {
            return "error: " + e.getClass().getName() + ":" + e.getLocalizedMessage();
        }
    }
}