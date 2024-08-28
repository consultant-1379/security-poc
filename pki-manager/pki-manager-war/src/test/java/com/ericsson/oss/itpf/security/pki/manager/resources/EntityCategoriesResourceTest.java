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
package com.ericsson.oss.itpf.security.pki.manager.resources;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
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

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.EntityCategorySetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link EntityCategoriesResource}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityCategoriesResourceTest {

    @InjectMocks
    EntityCategoriesResource entityCategoriesResource;

    @Mock
    private PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityCategoriesResource.class);

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    TestUtil testUtil;
    ObjectMapperUtilTest testObjectMapperUtil;

    List<EntityCategory> entityCategories;

    /**
     * Method for setting up test data
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        final EntityCategorySetUpToTest entityCategorySetUpToTest = new EntityCategorySetUpToTest();
        entityCategories = entityCategorySetUpToTest.getEntityCategories();

        testUtil = new TestUtil();
        testObjectMapperUtil = new ObjectMapperUtilTest();
        Mockito.when(pkiManagerEServiceProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService); 

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(entityCategoriesResource);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching {@link EntityCategoriesResource}
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException, JsonProcessingException, UnsupportedEncodingException {

        when(pkiConfigurationManagementService.listAllEntityCategories()).thenReturn(entityCategories);
        when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_CATEGORY_MAPPER)).thenReturn(new ObjectMapper());
        request = MockHttpRequest.get("/entitycategories/fetch");
        dispatcher.invoke(request, response);

        assertNotNull(response.getContentAsString());
        assertEquals(response.getStatus(), STATUS_OK);
    }

}
