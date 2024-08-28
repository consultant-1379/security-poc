/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.entityprofile;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.powermock.api.mockito.PowerMockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.EntityProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;

/**
 * This class will test EndEntityProfileResourceTest
 * 
 * @author tcsrav
 * 
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class EndEntityProfileResourceTest {

    @InjectMocks
    EndEntityProfileResource endEntityProfileResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(CAEntityProfileResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;
    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    MockHttpRequest request;
    MockHttpResponse response;
    Dispatcher dispatcher;

    @Before
    public void setUp() throws Exception {

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(endEntityProfileResource);
        response = new MockHttpResponse();
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService);

    }

    /**
     * Method to test testfetch Positive scenario
     * 
     */
    @Test
    public void testFetch() throws DatatypeConfigurationException, URISyntaxException, IOException {
        final EntityProfileSetUpToTest entityProfileSetUpToTest = new EntityProfileSetUpToTest();
        EntityProfile entityProfile = entityProfileSetUpToTest.getEntityProfile();
        ObjectMapperUtilTest testObjectMapperUtil = new ObjectMapperUtilTest();

        final Profiles profiles = new Profiles();
        List<EntityProfile> entityProfilesList = new ArrayList<EntityProfile>();
        entityProfilesList.add(entityProfile);
        profiles.setEntityProfiles(entityProfilesList);

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER));

        PowerMockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITIES_FETCH_MAPPER));

        Mockito.when(profileManagementService.exportProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(profiles);
        request = MockHttpRequest.get("/1.0/endentityprofile/fetch");

        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), 200);
    }

}
