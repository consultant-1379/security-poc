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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.certificateprofile;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

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
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.EntityManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;

/**
 * Test class for {@link IssuersResource}
 * 
 * @author xhemgan
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class IssuersResourceTest {

    @InjectMocks
    private IssuersResource issuers;

    @Spy
    Logger logger = LoggerFactory.getLogger(IssuersResource.class);

    @Mock
    private EntityManagementServiceLocal entityManagementServicelocal;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    private final static int STATUS_OK = 200;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    ObjectMapperUtilTest testObjectMapperUtil;

    Entities entities;

    /**
     * Method for setting up test data.
     * 
     * @throws IOException
     */
    @Before
    public void setup() throws IOException {

        entities = new Entities();
        entities.setCAEntities(getCAEntities());

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(issuers);

        testObjectMapperUtil = new ObjectMapperUtilTest();

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

        when(entityManagementServicelocal.fetchCAEntitiesIdAndName(CAStatus.ACTIVE, false)).thenReturn(entities.getCAEntities());
        when(objectMapperUtil.getObjectMapper(ObjectMapperType.ISSUER_ID_NAME_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ISSUER_ID_NAME_MAPPER));

        request = MockHttpRequest.get("/issuers/fetch");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
    }

}
