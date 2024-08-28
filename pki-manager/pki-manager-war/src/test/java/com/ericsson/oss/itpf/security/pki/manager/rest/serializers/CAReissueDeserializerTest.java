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
import static org.junit.Assert.assertNull;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.CAReissueDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link CAReissueDesializer}
 * 
 * @author tcsnapa
 */
public class CAReissueDeserializerTest {

    @Mock
    CAReissueDesializer caReissueDeserializer;

    ObjectMapper mapper;

    final CAReissueDTO caReissueDTO = new CAReissueDTO();

    @Before
    public void setUp() {

        mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        module.addDeserializer(CAReissueDTO.class, new CAReissueDesializer());
        mapper.registerModule(module);

        caReissueDTO.setName("TestCA");
        caReissueDTO.setRekey(true);
        caReissueDTO.setReIssueType(ReIssueType.CA);
        caReissueDTO.setRevocationReason(RevocationReason.KEY_COMPROMISE);
    }

    /**
     * Method to test CAReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testCAReissuedeSerialize() throws JsonProcessingException, IOException {

        final String inputJsonCAReissueDTO = "{\"name\":\"TestCA\",\"rekey\":true,\"reIssueType\":\"CA\",\"revocationReason\":\"KEY_COMPROMISE\"}";
        final CAReissueDTO expectedCAReissueDTO = mapper.readValue(inputJsonCAReissueDTO, CAReissueDTO.class);
        assertCAReissueDTO(expectedCAReissueDTO);
    }

    /**
     * Method to test CAReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testCAReissuedeSerialize_With_Int_RevocationReason() throws JsonProcessingException, IOException {

        final String inputJsonCAReissueDTO = "{\"name\":\"TestCA\",\"rekey\":true,\"reIssueType\":\"CA\",\"revocationReason\":\"1\"}";
        final CAReissueDTO expectedCAReissueDTO = mapper.readValue(inputJsonCAReissueDTO, CAReissueDTO.class);
        assertCAReissueDTO(expectedCAReissueDTO);
    }

    /**
     * Method to test CAReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testCAReissuedeSerialize_With_Invalid_RevocationReason() throws JsonProcessingException, IOException {

        final String inputJsonCAReissueDTO = "{\"name\":\"TestCA\",\"rekey\":true,\"reIssueType\":\"CA\",\"revocationReason\":\"20\"}";
        final CAReissueDTO expectedCAReissueDTO = mapper.readValue(inputJsonCAReissueDTO, CAReissueDTO.class);
        assertEquals(expectedCAReissueDTO.getName(), caReissueDTO.getName());
        assertEquals(expectedCAReissueDTO.getReIssueType(), caReissueDTO.getReIssueType());
        assertNull(expectedCAReissueDTO.getRevocationReason());
    }

    private void assertCAReissueDTO(final CAReissueDTO expectedCAReissueDTO) {
        assertEquals(expectedCAReissueDTO.getName(), caReissueDTO.getName());
        assertEquals(expectedCAReissueDTO.getReIssueType(), caReissueDTO.getReIssueType());
        assertEquals(expectedCAReissueDTO.getRevocationReason(), caReissueDTO.getRevocationReason());
    }
}
