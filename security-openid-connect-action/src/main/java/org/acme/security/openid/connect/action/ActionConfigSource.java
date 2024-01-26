package org.acme.security.openid.connect.action;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

public class ActionConfigSource implements ConfigSource {

	@Override
	public Set<String> getPropertyNames() {
		return providers.keySet();
	}

	@Override
	public String getValue(String propertyName) {
		return providers.get(propertyName);
	}

	@Override
	public String getName() {
		return "providers-config-source";
	}

	private static final Map<String, String> providers = 
			Map.of("google-client-id", "my-google-client-id",
				   "google-client-secret", "my-google-client-secret");
	
}
