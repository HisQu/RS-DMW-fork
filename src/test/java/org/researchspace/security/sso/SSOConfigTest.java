package org.researchspace.security.sso;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.config.Ini;
import org.apache.shiro.config.ogdl.ReflectionBuilder;
import org.junit.Test;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.researchspace.config.Configuration;
import org.researchspace.config.groups.EnvironmentConfiguration;
import org.researchspace.secrets.MapSecretResolver;
import org.researchspace.security.SecurityConfigRecord;
import org.researchspace.security.SecurityConfigType;
import org.researchspace.security.sso.utils.ConfigParameterListValueFactory;
import org.researchspace.security.sso.utils.ConfigParameterStringValueFactory;

import io.buji.pac4j.context.ShiroSessionStore;
import io.buji.pac4j.profile.ShiroProfileManager;

public class SSOConfigTest {
    @Test
    public void oidcFiltersExistInBundledPac4j() throws Exception {
        Ini ini = Ini.fromResourcePath(
                "classpath:org/researchspace/security/sso/shiro-sso-oidc-default.ini");
        for (String name : new String[] {"securityFilter", "callbackFilter", "logoutFilter"}) {
            Class.forName(ini.getSection("main").get(name)).asSubclass(Filter.class);
        }
    }

    @Test
    public void shippedOidcConfigConnectsProfilesToShiro() {
        Ini ini = Ini.fromResourcePath(
                "classpath:org/researchspace/security/sso/shiro-sso-oidc-default.ini");
        Map<String, String> bridge = new LinkedHashMap<>();
        bridge.put("config", ini.getSection("main").get("config"));
        bridge.put("pac4jToShiroBridge", ini.getSection("main").get("pac4jToShiroBridge"));
        bridge.put("pac4jToShiroBridge.config", ini.getSection("main").get("pac4jToShiroBridge.config"));
        Config config = (Config) new ReflectionBuilder().buildObjects(bridge).get("config");
        assertSame(ShiroSessionStore.INSTANCE, config.getSessionStore());
        assertTrue(config.getProfileManagerFactory().apply(mock(WebContext.class), ShiroSessionStore.INSTANCE)
                instanceof ShiroProfileManager);
    }

    @Test
    public void oidcParametersReachClientFromEnvironment() {
        Ini ini = environment(new MapSecretResolver()).parseConfig();
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String name : new String[] {"oidcDiscoveryUri", "clientId", "clientSecret", "roleJsonPaths"}) {
            parameters.put(name, ini.getSection("main").get(name));
            parameters.put(name + ".value", ini.getSection("main").get(name + ".value"));
        }
        Map<String, ?> objects = new ReflectionBuilder().buildObjects(parameters);
        assertEquals("http://fictional.invalid/.well-known/openid-configuration",
                ((ConfigParameterStringValueFactory) objects.get("oidcDiscoveryUri")).getInstance());
        assertEquals("fictional-client",
                ((ConfigParameterStringValueFactory) objects.get("clientId")).getInstance());
        assertEquals("fictional-secret",
                ((ConfigParameterStringValueFactory) objects.get("clientSecret")).getInstance());
        assertEquals(Arrays.asList("$.ext.roles"),
                ((ConfigParameterListValueFactory) objects.get("roleJsonPaths")).getInstance());
    }

    @Test
    public void customSecretReferencesStillResolve() {
        SSOEnvironment environment = environment(new MapSecretResolver()
                .addSecret("fictional.client", "configured-client")
                .addSecret("fictional.secret", "configured-secret"));
        Ini override = new Ini();
        override.load("[main]\nclientId.value = \\${fictional.client}\n"
                + "clientSecret.value = \\${fictional.secret}\n");
        environment.setIni(override);
        Ini ini = environment.parseConfig();
        assertEquals("configured-client", ini.getSection("main").get("clientId.value"));
        assertEquals("configured-secret", ini.getSection("main").get("clientSecret.value"));
    }

    private SSOEnvironment environment(MapSecretResolver resolver) {
        Configuration config = mock(Configuration.class);
        EnvironmentConfiguration settings = mock(EnvironmentConfiguration.class);
        SecurityConfigRecord missing = mock(SecurityConfigRecord.class);
        when(config.getEnvironmentConfig()).thenReturn(settings);
        when(settings.getSso()).thenReturn("oidc");
        when(settings.getSecurityConfig(SecurityConfigType.ShiroUsers)).thenReturn(missing);
        when(settings.getSecurityConfig(SecurityConfigType.SsoConfig)).thenReturn(missing);
        return new SSOEnvironment(null, config, null, resolver);
    }
}
