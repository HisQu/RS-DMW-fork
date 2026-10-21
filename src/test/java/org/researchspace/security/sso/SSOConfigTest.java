package org.researchspace.security.sso;

import javax.servlet.Filter;

import org.apache.shiro.config.Ini;
import org.junit.Test;

public class SSOConfigTest {
    @Test
    public void oidcFiltersExistInBundledPac4j() throws Exception {
        Ini ini = Ini.fromResourcePath(
                "classpath:org/researchspace/security/sso/shiro-sso-oidc-default.ini");
        for (String name : new String[] {"securityFilter", "callbackFilter", "logoutFilter"}) {
            Class.forName(ini.getSection("main").get(name)).asSubclass(Filter.class);
        }
    }
}
