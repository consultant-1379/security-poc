/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.trustprofile;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;

/**
 * Test class for {@link TrustedCAResource}
 * 
 * @author xhemgan
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustedCAResourceTest {

    @InjectMocks
    private TrustedCAResource trustedCAResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(TrustedCAResource.class);

    @Mock
    private EntityManagementService entityManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    ObjectMapperUtilTest testObjectMapperUtil;

    private final static int STATUS_OK = 200;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    Entities entities;

    /**
     * Method for setting up test data
     * 
     * @throws IOException
     */
    @Before
    public void setup() throws IOException {

        entities = new Entities();
        entities.setCAEntities(getCAEntities());

        testObjectMapperUtil = new ObjectMapperUtilTest();

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(trustedCAResource);
        response = new MockHttpResponse();
    }

    private List<CAEntity> getCAEntities() {
        final List<CAEntity> cAEntities = new ArrayList<CAEntity>();
        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority ca = new CertificateAuthority();
        ca.setId(1);
        ca.setName("ca1");
        ca.setStatus(CAStatus.NEW);
        caEntity.setCertificateAuthority(ca);
        caEntity.setType(EntityType.CA_ENTITY);
        cAEntities.add(caEntity);
        return cAEntities;
    }

    /**
     * Method to test the rest service for fetching {@link CAEntity}
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException {
        final List<EntityType> entityTypes = new ArrayList<EntityType>();
        entityTypes.add(EntityType.CA_ENTITY);

        when(entityManagementService.getEntities(entityTypes.toArray(new EntityType[entityTypes.size()]))).thenReturn(entities);
        when(objectMapperUtil.getObjectMapper(ObjectMapperType.TRUSTED_CA_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.TRUSTED_CA_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getEntityManagementService()).thenReturn(entityManagementService); 

        request = MockHttpRequest.get("/trustedCA/fetch");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
    }

}
