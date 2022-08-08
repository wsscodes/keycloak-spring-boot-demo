//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.keycloak.adapters;

import java.util.Iterator;
import java.util.List;
import javax.security.cert.X509Certificate;
import org.jboss.logging.Logger;
import org.keycloak.adapters.OIDCAuthenticationError.Reason;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;

public class BearerTokenRequestAuthenticator {
    protected Logger log = Logger.getLogger(BearerTokenRequestAuthenticator.class);
    protected String tokenString;
    protected AccessToken token;
    protected String surrogate;
    protected AuthChallenge challenge;
    protected KeycloakDeployment deployment;

    public BearerTokenRequestAuthenticator(KeycloakDeployment deployment) {
        this.deployment = deployment;
    }

    public AuthChallenge getChallenge() {
        return this.challenge;
    }

    public String getTokenString() {
        return this.tokenString;
    }

    public AccessToken getToken() {
        return this.token;
    }

    public String getSurrogate() {
        return this.surrogate;
    }

    public AuthOutcome authenticate(HttpFacade exchange) {
        List<String> authHeaders = exchange.getRequest().getHeaders("Authorization");
        if (authHeaders != null && !authHeaders.isEmpty()) {
            this.tokenString = null;
            Iterator var3 = authHeaders.iterator();

            while(var3.hasNext()) {
                String authHeader = (String)var3.next();
                String[] split = authHeader.trim().split("\\s+");
                if (split.length == 2 && split[0].equalsIgnoreCase("Bearer")) {
                    this.tokenString = split[1];
                    this.log.debugf("Found [%d] values in authorization header, selecting the first value for Bearer.", authHeaders.size());
                    break;
                }
            }

            if (this.tokenString == null) {
                this.challenge = this.challengeResponse(exchange, Reason.NO_BEARER_TOKEN, (String)null, (String)null);
                return AuthOutcome.NOT_ATTEMPTED;
            } else {
                return this.authenticateToken(exchange, this.tokenString);
            }
        } else {
            this.challenge = this.challengeResponse(exchange, Reason.NO_BEARER_TOKEN, (String)null, (String)null);
            return AuthOutcome.NOT_ATTEMPTED;
        }
    }

    protected AuthOutcome authenticateToken(HttpFacade exchange, String tokenString) {
        this.log.debug("Verifying access_token");
        if (this.log.isTraceEnabled()) {
            try {
                JWSInput jwsInput = new JWSInput(tokenString);
                String wireString = jwsInput.getWireString();
                this.log.tracef("\taccess_token: %s", wireString.substring(0, wireString.lastIndexOf(".")) + ".signature");
            } catch (JWSInputException var8) {
                this.log.errorf(var8, "Failed to parse access_token: %s", tokenString);
            }
        }

        try {
            this.token = AdapterTokenVerifier.verifyToken(tokenString, this.deployment);
        } catch (VerificationException var7) {
            this.log.debug("Failed to verify token");
            this.challenge = this.challengeResponse(exchange, Reason.INVALID_TOKEN, "invalid_token", var7.getMessage());
            return AuthOutcome.FAILED;
        }

        if (this.token.getIssuedAt() < this.deployment.getNotBefore()) {
            this.log.debug("Stale token");
            this.challenge = this.challengeResponse(exchange, Reason.STALE_TOKEN, "invalid_token", "Stale token");
            return AuthOutcome.FAILED;
        } else {
            boolean verifyCaller = false;
            if (this.deployment.isUseResourceRoleMappings()) {
                verifyCaller = this.token.isVerifyCaller(this.deployment.getResourceName());
            } else {
                verifyCaller = this.token.isVerifyCaller();
            }

            this.surrogate = null;
            if (verifyCaller) {
                if (this.token.getTrustedCertificates() == null || this.token.getTrustedCertificates().isEmpty()) {
                    this.log.warn("No trusted certificates in token");
                    this.challenge = this.clientCertChallenge();
                    return AuthOutcome.FAILED;
                }

                X509Certificate[] chain = new X509Certificate[0];

                try {
                    chain = exchange.getCertificateChain();
                } catch (Exception var6) {
                }

                if (chain == null || chain.length == 0) {
                    this.log.warn("No certificates provided by undertow to verify the caller");
                    this.challenge = this.clientCertChallenge();
                    return AuthOutcome.FAILED;
                }

                this.surrogate = chain[0].getSubjectDN().getName();
            }

            this.log.debug("successful authorized");
            return AuthOutcome.AUTHENTICATED;
        }
    }

    protected AuthChallenge clientCertChallenge() {
        return new AuthChallenge() {
            public int getResponseCode() {
                return 0;
            }

            public boolean challenge(HttpFacade exchange) {
                return false;
            }
        };
    }

    protected AuthChallenge challengeResponse(HttpFacade facade, final Reason reason, String error, final String description) {
        StringBuilder header = new StringBuilder("Bearer realm=\"");
        header.append(this.deployment.getRealm()).append("\"");
        if (error != null) {
            header.append(", error=\"").append(error).append("\"");
        }

        if (description != null) {
            header.append(", error_description=\"").append(description).append("\"");
        }

        final String challenge = header.toString();
        return new AuthChallenge() {
            public int getResponseCode() {
                return 401;
            }

            public boolean challenge(HttpFacade facade) {
                if (BearerTokenRequestAuthenticator.this.deployment.getPolicyEnforcer() != null) {
                    BearerTokenRequestAuthenticator.this.deployment.getPolicyEnforcer().enforce((OIDCHttpFacade)OIDCHttpFacade.class.cast(facade));
                    return true;
                } else {
                    OIDCAuthenticationError error = new OIDCAuthenticationError(reason, description);
                    facade.getRequest().setError(error);
                    facade.getResponse().addHeader("WWW-Authenticate", challenge);
                    if (BearerTokenRequestAuthenticator.this.deployment.isDelegateBearerErrorResponseSending()) {
                        facade.getResponse().setStatus(401);
                    } else {
                        facade.getResponse().sendError(401);
                    }

                    return true;
                }
            }
        };
    }
}
