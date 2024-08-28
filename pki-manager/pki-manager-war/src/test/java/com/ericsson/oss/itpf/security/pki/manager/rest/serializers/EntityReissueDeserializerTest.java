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

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityReissueDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link EntityReissueDeSerializer}
 * 
 * @author tcsnapa
 */
public class EntityReissueDeserializerTest {

    @Mock
    EntityReissueDeSerializer entityReissueDeSerializer;

    ObjectMapper mapper;

    final EntityReissueDTO entityReissueDTO = new EntityReissueDTO();

    @Before
    public void setUp() {

        mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        module.addDeserializer(EntityReissueDTO.class, new EntityReissueDeSerializer());
        mapper.registerModule(module);

        entityReissueDTO.setChain(true);
        entityReissueDTO.setFormat(KeyStoreType.PKCS12);
        entityReissueDTO.setName("TestEntity");
        entityReissueDTO.setPassword("secret");
        entityReissueDTO.setRevocationReason(RevocationReason.PRIVILEGE_WITHDRAWN);
    }

    /**
     * Method to test EntityReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testEntityReissuedeSerialize() throws JsonProcessingException, IOException {

        final String inputJsonEntityReissueDTO = "{\"name\":\"TestEntity\",\"chain\":true,\"format\":\"PKCS12\",\"password\":\"secret\",\"revocationReason\":\"PRIVILEGE_WITHDRAWN\"}";
        final EntityReissueDTO expectedEntityReissueDTO = mapper.readValue(inputJsonEntityReissueDTO, EntityReissueDTO.class);
        assertEntityReissueDTO(expectedEntityReissueDTO);

    }

    /**
     * Method to test EntityReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testEntityReissuedeSerialize_With_Int_RevocationReason() throws JsonProcessingException, IOException {

        final String inputJsonEntityReissueDTO = "{\"name\":\"TestEntity\",\"chain\":true,\"format\":\"PKCS12\",\"password\":\"secret\",\"revocationReason\":\"9\"}";
        final EntityReissueDTO expectedEntityReissueDTO = mapper.readValue(inputJsonEntityReissueDTO, EntityReissueDTO.class);
        assertEntityReissueDTO(expectedEntityReissueDTO);
    }

    /**
     * Method to test EntityReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testEntityReissuedeSerialize_With_Invalid_RevocationReason() throws JsonProcessingException, IOException {

        final String inputJsonCAReissueDTO = "{\"name\":\"TestEntity\",\"chain\":true,\"format\":\"PKCS12\",\"password\":\"secret\",\"revocationReason\":\"20\"}";
        final EntityReissueDTO expectedEntityReissueDTO = mapper.readValue(inputJsonCAReissueDTO, EntityReissueDTO.class);
        assertEquals(expectedEntityReissueDTO.getName(), entityReissueDTO.getName());
        assertEquals(expectedEntityReissueDTO.getFormat(), entityReissueDTO.getFormat());
        assertEquals(expectedEntityReissueDTO.getPassword(), entityReissueDTO.getPassword());
        assertNull(expectedEntityReissueDTO.getRevocationReason());
    }

    private void assertEntityReissueDTO(final EntityReissueDTO expectedEntityReissueDTO) {
        assertEquals(expectedEntityReissueDTO.getName(), entityReissueDTO.getName());
        assertEquals(expectedEntityReissueDTO.getFormat(), entityReissueDTO.getFormat());
        assertEquals(expectedEntityReissueDTO.getPassword(), entityReissueDTO.getPassword());
        assertEquals(expectedEntityReissueDTO.getRevocationReason(), entityReissueDTO.getRevocationReason());
    }

}
