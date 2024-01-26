package org.acme.security.openid.connect.proxy;

import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "oidc-proxy")
public interface OidcProxyConfig {

    /**
     *  Allow to return a refresh token from the authorization code grant response
     */
    @WithDefault("true")
    boolean allowRefreshToken();
    
    /**
     *  OIDC proxy authorization endpoint path
     */
    @WithDefault("/oidc/authorize")
    String authorizationPath();
    
    /**
     *  OIDC proxy token endpoint path
     */
    @WithDefault("/oidc/token")
    String tokenPath();
    
    /**
     *  OIDC proxy JSON Web Key Set endpoint path
     */
    @WithDefault("/oidc/jwks")
    String jwksPath();
    
    /**
     *  Absolute external redirect URI.
     *  <p/> 
     *  If 'quarkus.oidc.authentication.redirect-path' is configured then configuring this proxy is required.
     *  In this case, the proxy will request a redirect to 'quarkus.oidc.authentication.redirect-path' and
     *  will redirect further to  the external config path.  
     */
    Optional<String> externalRedirectUri();
}
