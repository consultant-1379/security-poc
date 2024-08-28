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
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link RevocationReasonSerializer}
 * 
 * @author xramdag
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class RevocationReasonSerializerTest {

    @Mock
    RevocationReasonSerializer revocationReasonSerializer;

    RevocationReason revocationReason;

    ObjectMapper mapper;

    @Before
    public void setUp() {

        mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason.class, new RevocationReasonSerializer());

        mapper.registerModule(module);

        revocationReason = RevocationReason.getNameByValue(1);

    }

    /**
     * Method for Serialize()
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testSerialize() throws JsonProcessingException {

        final String expectedOutput = "{\"id\":1,\"name\":\"KEY_COMPROMISE\"}";
        final String jsonOutput = mapper.writeValueAsString(revocationReason);
        assertEquals(expectedOutput, jsonOutput);
    }

}
