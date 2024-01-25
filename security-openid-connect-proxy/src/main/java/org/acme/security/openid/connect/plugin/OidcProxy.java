package org.acme.security.openid.connect.plugin;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.logging.Log;
import io.quarkus.oidc.OidcConfigurationMetadata;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

@ApplicationScoped
public class OidcProxy {
    @Inject
    Vertx vertx;
    WebClient client;
    
    final OidcConfigurationMetadata oidcMetadata;
    final OidcTenantConfig oidcTenantConfig;
    final OidcProxyConfig oidcProxyConfig;
    
    public OidcProxy(TenantConfigBean tenantConfig, OidcProxyConfig oidcProxyConfig) {
    	this.oidcTenantConfig = tenantConfig.getDefaultTenant().getOidcTenantConfig();
    	this.oidcMetadata = tenantConfig.getDefaultTenant().getOidcMetadata();
    	this.oidcProxyConfig = oidcProxyConfig;
    }
    
    @PostConstruct
    void initWebClient() {
        client = WebClient.create(vertx, new WebClientOptions());
    }
    
    @PreDestroy
    void closeVertxClient() {
        if (client != null) {
            client.close();
            client = null;
        }
    }
    
    public void setup(@Observes Router router) {
    	router.route(oidcProxyConfig.authorizationPath()).handler(new AuthorizationRouteHandler());
        router.route(oidcProxyConfig.tokenPath()).handler(new TokenRouteHandler());
        router.route(oidcProxyConfig.jwksPath()).handler(new JwksRouteHandler());
        if (oidcTenantConfig.authentication.redirectPath.isPresent()) {
        	if (!oidcProxyConfig.externalRedirectUri().isPresent()) {
        		throw new ConfigurationException("oidc-proxy.external-redirect-uri property must be configured because"
        				+ "the local quarkus.oidc.authentication.redirect-path is configured");
        	}
        	router.route(oidcTenantConfig.authentication.redirectPath.get()).handler(new LocalRedirectRouteHandler());
        }
    }

    private class AuthorizationRouteHandler implements Handler<RoutingContext> {
        @Override
        public void handle(RoutingContext context) {
        	Log.info("OidcProxy: authorize");
        	MultiMap queryParams = context.queryParams();
        	        	
        	StringBuilder codeFlowParams = new StringBuilder(168); // experimentally determined to be a good size for preventing resizing and not wasting space

            // response_type
            codeFlowParams.append(OidcConstants.CODE_FLOW_RESPONSE_TYPE).append("=")
                    .append(OidcConstants.CODE_FLOW_CODE);
            // client_id
            codeFlowParams.append("&").append(OidcConstants.CLIENT_ID).append("=")
                    .append(urlEncode(getClientId(queryParams.get(OidcConstants.CLIENT_ID))));
            // scope
            codeFlowParams.append("&").append(OidcConstants.TOKEN_SCOPE).append("=")
                    .append(encodeScope(queryParams.get(OidcConstants.TOKEN_SCOPE)));
            // state
            codeFlowParams.append("&").append(OidcConstants.CODE_FLOW_STATE).append("=")
                    .append(queryParams.get(OidcConstants.CODE_FLOW_STATE));

            // redirect_uri
            codeFlowParams.append("&").append(OidcConstants.CODE_FLOW_REDIRECT_URI).append("=")
                    .append(urlEncode(getRedirectUri(context, queryParams.get(OidcConstants.CODE_FLOW_REDIRECT_URI))));

            String authorizationURL = oidcMetadata.getAuthorizationUri() + "?"  + codeFlowParams.toString();
            
            context.response().setStatusCode(HttpResponseStatus.FOUND.code());
            context.response().putHeader(HttpHeaders.LOCATION, authorizationURL);
            context.response().end();
        }
    }
    
    private class LocalRedirectRouteHandler implements Handler<RoutingContext> {
        @Override
        public void handle(RoutingContext context) {
        	Log.info("OidcProxy: local redirect");
        	MultiMap queryParams = context.queryParams();
        	        	
        	StringBuilder codeFlowParams = new StringBuilder(168); // experimentally determined to be a good size for preventing resizing and not wasting space

        	// code
            codeFlowParams.append(OidcConstants.CODE_FLOW_CODE).append("=")
                    .append(queryParams.get(OidcConstants.CODE_FLOW_CODE));
            // state
            codeFlowParams.append("&").append(OidcConstants.CODE_FLOW_STATE).append("=")
                    .append(queryParams.get(OidcConstants.CODE_FLOW_STATE));

            String redirectURL = oidcProxyConfig.externalRedirectUri().get() + "?"  + codeFlowParams.toString();
            
            context.response().setStatusCode(HttpResponseStatus.FOUND.code());
            context.response().putHeader(HttpHeaders.LOCATION, redirectURL);
            context.response().end();
        }
    }
    
    private class TokenRouteHandler implements Handler<RoutingContext> {
        @Override
        public void handle(RoutingContext context) {
            OidcUtils.getFormUrlEncodedData(context)
            .onItem().transformToUni(new Function<MultiMap, Uni<? extends Void>>() {
                @Override
                public Uni<Void> apply(MultiMap requestParams) {
                	Log.info("OidcProxy: Token exchange: start");	                    
                	HttpRequest<Buffer> request = client.postAbs(oidcMetadata.getTokenUri());
                    request.putHeader(String.valueOf(HttpHeaders.CONTENT_TYPE), String
                            .valueOf(HttpHeaders.APPLICATION_X_WWW_FORM_URLENCODED));
                    request.putHeader(String.valueOf(HttpHeaders.ACCEPT), "application/json");
                    
                    Buffer buffer = Buffer.buffer();
                    encodeForm(buffer, OidcConstants.GRANT_TYPE, requestParams.get(OidcConstants.GRANT_TYPE));
                    encodeForm(buffer, OidcConstants.CLIENT_ID, getClientId(requestParams.get(OidcConstants.CLIENT_ID)));
                    encodeForm(buffer, OidcConstants.CLIENT_SECRET, getClientSecret(requestParams.get(OidcConstants.CLIENT_SECRET)));
                    if (!requestParams.contains(OidcConstants.REFRESH_TOKEN_VALUE)) {
            	        encodeForm(buffer, OidcConstants.CODE_FLOW_CODE, requestParams.get(OidcConstants.CODE_FLOW_CODE));
            	        encodeForm(buffer, OidcConstants.CODE_FLOW_REDIRECT_URI, getRedirectUri(context, requestParams.get(OidcConstants.CODE_FLOW_REDIRECT_URI)));
                    } else {
                    	encodeForm(buffer, OidcConstants.REFRESH_TOKEN_VALUE, requestParams.get(OidcConstants.REFRESH_TOKEN_VALUE));
                    }

                    Uni<HttpResponse<Buffer>> response = request.sendBuffer(buffer);
                    return response.onItemOrFailure().transformToUni(new BiFunction<HttpResponse<Buffer>,
                    		Throwable, Uni<? extends Void>>() {
            					@Override
            					public Uni<Void> apply(HttpResponse<Buffer> t, Throwable u) {
            						Log.info("OidcProxy: Token exchange: end");	                    
            				
            						if (!oidcProxyConfig.allowRefreshToken() && OidcConstants.AUTHORIZATION_CODE.equals
            								(requestParams.get(OidcConstants.GRANT_TYPE))) {
            							JsonObject body = t.bodyAsJsonObject();
            							body.remove(OidcConstants.REFRESH_TOKEN_VALUE);
            							endJsonResponse(context, body.toString());
            						} else {
            							endJsonResponse(context, t.bodyAsString());
            						}
            						return Uni.createFrom().voidItem();
            					}
                    });
                }
            }).subscribe().with(new Consumer<Void>() {
                        @Override
                        public void accept(Void response) {
                        }
                    });
        }
    }
    
    private class JwksRouteHandler implements Handler<RoutingContext> {
        @Override
        public void handle(RoutingContext context) {
        	Log.info("OidcProxy: Get JWK");	                    
    	    client.getAbs(oidcMetadata.getJsonWebKeySetUri()).send()
    	      .subscribe().with(new Consumer<HttpResponse<Buffer>>() {
                  @Override
                  public void accept(HttpResponse<Buffer> response) {
                	  endJsonResponse(context, response.bodyAsString());
                  }
              });
        }    
    }
    
    private static void endJsonResponse(RoutingContext context, String jsonResponse) {
    	context.response().setStatusCode(HttpResponseStatus.OK.code());
        context.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json");
  	    context.end(jsonResponse);
    }
    
    public static void encodeForm(Buffer buffer, String name, String value) {
        if (buffer.length() != 0) {
            buffer.appendByte((byte)'&');
        }
        buffer.appendString(name);
        buffer.appendByte((byte)'=');
        buffer.appendString(urlEncode(value));
    }

    public static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    
    private String getClientId(String providedClientId) {
    	return oidcTenantConfig.clientId.orElse(providedClientId);
    }
    
    private String getClientSecret(String providedClientSecret) {
    	String configuredClientSecret = OidcCommonUtils.clientSecret(oidcTenantConfig.credentials);
    	return configuredClientSecret == null ? providedClientSecret : configuredClientSecret;
    }

    private String getRedirectUri(RoutingContext context, String redirectUri) {
		if (oidcTenantConfig.authentication.redirectPath.isPresent()) {
			return buildUri(context, oidcTenantConfig.authentication.redirectPath.get());
		} else {
		    return redirectUri;
		}
	}
    
    private String encodeScope(String providedScope) {
    	List<String> configuredScopes = oidcTenantConfig.authentication.scopes.orElse(List.of("openid"));
        Set<String> scopes = new HashSet<>();
        scopes.addAll(configuredScopes);
        if (providedScope != null) {
        	scopes.add(providedScope);
        }
        StringBuilder sb = new StringBuilder();
        for (String scope : scopes) {
        	if (sb.length() != 0) {
        		sb.append("%20");
            }
            sb.append(urlEncode(scope));
        }
        return sb.toString();
	}
    
    private String buildUri(RoutingContext context, String path) {
        final String authority = URI.create(context.request().absoluteURI()).getAuthority();
        final String scheme = oidcTenantConfig.authentication.forceRedirectHttpsScheme.isPresent() ? "https" : context.request().scheme();
        return new StringBuilder(scheme).append("://")
                .append(authority)
                .append(path)
                .toString();
    }
}
