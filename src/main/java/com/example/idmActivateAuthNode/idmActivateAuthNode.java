/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package com.example.idmActivateAuthNode;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import java.util.Map;
import java.util.List;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.Client;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.json.JsonValue;


/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = idmActivateAuthNode.Config.class)
public class idmActivateAuthNode extends AbstractDecisionNode {

    private final Pattern DN_PATTERN = Pattern.compile("^[a-zA-Z0-9]=([^,]+),");
    private final Logger logger = LoggerFactory.getLogger(idmActivateAuthNode.class);
    private final Config config;
    private final Realm realm;

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * IDM Base URL
         */
        @Attribute(order = 100)
        String idmBaseUrl();

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public idmActivateAuthNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        Map requestParameters = context.request.parameters;

        try {
            List<String> tokenList = context.request.parameters.get("token");
            List<String> codeList = context.request.parameters.get("code");

            logger.error("got parameters {}",requestParameters.toString());
            if (tokenList == null || codeList == null) {
                throw new NodeProcessException("Didn't receive required parameters");
            }

            String token = tokenList.get(0);
            String code  = codeList.get(0);
            String idmUrl = config.idmBaseUrl() + "/openidm/selfservice/registration?_action=submitRequirements";
            String body = "{\n" +
                    "  \"input\": {\n" +
                    "    \"token\": \"" + token + "\",\n" +
                    "    \"code\": \"" + code + "\"\n" +
                    "  },\n" +
                    "  \"token\": \"" + token + "\"\n" +
                    "}";

            logger.error("code {} token {}",code,token);
            logger.error("IDM URL {}",idmUrl);

            URL url = new URL(idmUrl);

            //Build HTTP request

            Request req = new Request();

            req.setMethod("POST");
            req.setUri(idmUrl);
            req.getHeaders().add("X-OpenIDM-Username","anonymous");
            req.getHeaders().add("X-OpenIDM-Password","anonymous");
            req.getHeaders().add("Content-Type","application/json");
            req.setEntity(body);

            HttpClientHandler clientHandler = new HttpClientHandler();
            Client httpClient = new Client(clientHandler);

            Response response = httpClient.send(req).get();
            String responseContent = response.getEntity().toString();
            String responseStatus = response.getStatus().toString();

            logger.error("status " + responseStatus);
            logger.error("entity " + responseContent);

            if (!responseStatus.toString().contains("200")) {
                logger.error("Bad response from IDM");
                throw new NodeProcessException("Bad response from IDM " + responseStatus.toString());
            }

            JsonValue responseJson = new JsonValue(Utils.parseJson(responseContent));
            String successUrl = responseJson.get("additions").get("successUrl").asString();
            logger.error("got success Url " + successUrl);

            return goTo(true).build();
        } catch (Exception e) {
            logger.error("Error " + e);
        }
        return goTo(false).build();
    }

}
