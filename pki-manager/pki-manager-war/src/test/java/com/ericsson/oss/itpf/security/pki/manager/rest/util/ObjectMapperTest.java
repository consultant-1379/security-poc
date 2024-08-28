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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * This class will test ObjectMapperTest
 * 
 * @author tcsrav
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class ObjectMapperTest {

    ObjectMapperUtil objectMapperUtil;

    @Before
    public void setUp() throws Exception {
        objectMapperUtil = new ObjectMapperUtil();
    }

    /**
     * Method to test Positive scenario
     * 
     */
    @Test
    public void getObjectMapperTest() throws IOException {

        objectMapperUtil.startup();
        objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_CATEGORY_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.ACCESS_METHOD_MAPPER);

        assertNotNull(objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER));

        objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_PURPOSE_ID_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_USAGE_TYPE_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.EXTENDED_KEY_USAGE_TYPE_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_ALT_NAME_TYPE_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_SERIALIZER_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_DESERIALIZER_MAPPER);

        assertNotNull(objectMapperUtil.getObjectMapper(ObjectMapperType.TRUSTED_CA_MAPPER));

    }

    @Test
    public void getProfilesFetchMapperTest() throws IOException {

        objectMapperUtil.startup();
        objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_FIELD_TYPE_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_GEN_ALGORITHM_SEIALIZER_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_ALT_NAME_EXTENSION_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_CAPABILITIES_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_CATEGORY_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER);

        assertNotNull(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITIES_FETCH_MAPPER));

        objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_FETCH_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_FETCH_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_DESERIALIZER_MAPPER);
        objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MODEL_MAPPER);

        assertNotNull(objectMapperUtil.getObjectMapper(ObjectMapperType.PROFILES_FETCH_MAPPER));
    }

}
