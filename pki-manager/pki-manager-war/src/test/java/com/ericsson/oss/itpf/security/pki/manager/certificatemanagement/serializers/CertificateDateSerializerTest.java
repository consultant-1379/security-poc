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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.serializers;

import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.powermock.api.mockito.PowerMockito;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

@RunWith(MockitoJUnitRunner.class)
public class CertificateDateSerializerTest {

    @InjectMocks
    CertificateDateSerializer certificateDateSerializer;

    @Mock
    JsonGenerator generator;

    @Mock
    SerializerProvider provider;

    ObjectMapper mapper;

    @Before
    public void setUp() {

        mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        certificateDateSerializer = new CertificateDateSerializer();
        mapper.registerModule(module);
    }

    /**
     * Method for Date Serialize()
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testSerialize() throws JsonProcessingException, IOException {
        final Date date = new Date();
        PowerMockito.mockStatic(JsonGenerator.class);
        PowerMockito.mockStatic(SerializerProvider.class);
        certificateDateSerializer.serialize(date, generator, provider);
    }
}
