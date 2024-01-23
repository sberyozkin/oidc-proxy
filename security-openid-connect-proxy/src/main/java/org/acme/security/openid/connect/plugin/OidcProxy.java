package org.acme.security.openid.connect.plugin;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.logging.Log;
import io.quarkus.oidc.OidcConfigurationMetadata;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

@Path("/oidc")
public class OidcProxy {
    @Inject
    OidcConfigurationMetadata metadata;
    
    @Inject
    TenantConfigBean oidcTenantConfig;
    
    @Inject
    @ConfigProperty(name = "oidc-proxy.allow-refresh-token", defaultValue = "true")
    boolean allowRefreshToken;

    @Inject
    Vertx vertx;
    WebClient client;

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
    
    @GET
    @Path("authorize")
    public Uni<Response> authorize(@QueryParam("response_type") String responseType,
						    	   @QueryParam("client_id") String clientId,
						    	   @QueryParam("scope") String scope,
						    	   @QueryParam("state") String state,
						    	   @QueryParam("redirect_uri") String redirectUri) {
        Log.info("OidcProxy: authorize");
        
    	URI oidcAuthorizationUri = UriBuilder.fromUri(metadata.getAuthorizationUri())
    	   .queryParam("response_type", responseType)
    	   .queryParam("client_id", urlEncode(getClientId(clientId)))
    	   .queryParam("scope", encodeScope(scope))
    	   .queryParam("state", state)
    	   .queryParam("redirect_uri", redirectUri)
    	   .build();
    	return Uni.createFrom().item(Response.seeOther(oidcAuthorizationUri).build());
    }
    
    @POST
    @Path("token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<String> token(@FormParam("grant_type") String grantType,
    		                 @FormParam("client_id") String clientId,
    		                 @FormParam("client_secret") String clientSecret,
    		                 @FormParam("code") String code,
    		                 @FormParam("redirect_uri") String redirectUri,
    		                 @FormParam("refresh_token") String refreshToken) {
    	Log.info("OidcProxy: Token exchange: start");	                    
    	HttpRequest<Buffer> request = client.postAbs(metadata.getTokenUri());
        request.putHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);
        request.putHeader("Accept", MediaType.APPLICATION_JSON);
        
        Buffer buffer = Buffer.buffer();
        encodeForm(buffer, "grant_type", grantType);
        encodeForm(buffer, "client_id", getClientId(clientId));
        encodeForm(buffer, "client_secret", getClientSecret(clientSecret));
        if (refreshToken == null) {
	        encodeForm(buffer, "code", code);
	        encodeForm(buffer, "redirect_uri", redirectUri);
        } else {
        	encodeForm(buffer, "refresh_token", refreshToken);
        }

        Uni<HttpResponse<Buffer>> response = request.sendBuffer(buffer);
        return response.onItemOrFailure().transform(new BiFunction<HttpResponse<Buffer>,
        		Throwable, String>() {

					@Override
					public String apply(HttpResponse<Buffer> t, Throwable u) {
						Log.info("OidcProxy: Token exchange: end");	                    
						
						if (!allowRefreshToken && "authorization_code".equals(grantType)) {
							JsonObject body = t.bodyAsJsonObject();
							body.remove("refresh_token");
							return body.toString();
						} else {
						    return t.bodyAsString();
						}
					}
        	
        });
    }
    
    @GET
    @Path("jwks")
    @Produces("application/json")
    public Uni<String> jwks() {
        Log.info("OidcProxy: Get JWK");	                    
	    return client.getAbs(metadata.getJsonWebKeySetUri()).send().onItem()
	    		.transform(t -> t.bodyAsString());
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
    	return oidcTenantConfig.getDefaultTenant().getOidcTenantConfig().clientId.orElse(providedClientId);
    }
    
    private String getClientSecret(String providedClientSecret) {
    	String configuredClientSecret = OidcCommonUtils.clientSecret(oidcTenantConfig.getDefaultTenant().getOidcTenantConfig().credentials);
    	return configuredClientSecret == null ? providedClientSecret : configuredClientSecret;
    }
    
    private String encodeScope(String providedScope) {
    	List<String> configuredScopes = oidcTenantConfig.getDefaultTenant().getOidcTenantConfig().authentication
        		.scopes.orElse(List.of("openid"));
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
}
