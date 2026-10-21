package org.researchspace.repository;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.researchspace.repository.sparql.bearertoken.SPARQLBearerTokenAuthRepository;
import org.researchspace.repository.sparql.bearertoken.SPARQLBearerTokenAuthRepositoryConfig;
import org.researchspace.repository.sparql.bearertoken.SPARQLBearerTokenAuthRepositoryFactory;

public class SPARQLBearerTokenAuthRepositoryFactoryTest {
    @Test
    public void factoryHonorsWritableForBothEndpointConfigurations() {
        for (boolean writable : new boolean[] {true, false}) {
            for (String updateEndpoint : new String[] {null, "http://fictional.invalid/update"}) {
                SPARQLBearerTokenAuthRepositoryConfig config = new SPARQLBearerTokenAuthRepositoryConfig();
                config.setQueryEndpointUrl("http://fictional.invalid/sparql");
                config.setUpdateEndpointUrl(updateEndpoint);
                config.setAuthenticationToken("fictional-token");
                config.setWritable(writable);
                SPARQLBearerTokenAuthRepository repository = (SPARQLBearerTokenAuthRepository)
                        new SPARQLBearerTokenAuthRepositoryFactory().getRepository(config);
                assertEquals(writable, repository.isWritable());
                assertEquals("fictional-token", repository.getAuthenticationToken());
            }
        }
    }
}
