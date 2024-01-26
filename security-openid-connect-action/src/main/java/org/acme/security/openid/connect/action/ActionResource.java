package org.acme.security.openid.connect.action;

import io.quarkus.logging.Log;
import io.quarkus.oidc.UserInfo;
import io.quarkus.security.Authenticated;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

@Path("/action")
@Authenticated
public class ActionResource {

    @Inject
    UserInfo principal;

    @GET
    @Produces("text/plain")
    @Path("name")
    public Uni<String> userName() {
        Log.info("Action resource: getName()");
        return Uni.createFrom().item(principal.getName());
    }
    
}
