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
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.KeyStoreFileDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link ReissueWithCSRDeSerializer}
 * 
 * @author tcsnapa
 */
public class ReissueWithCSRDeserializerTest {

    @Mock
    ReissueWithCSRDeSerializer reissueWithCSRDeSerializer;

    ObjectMapper mapper;

    final KeyStoreFileDTO keyStoreFileDTO = new KeyStoreFileDTO();

    @Before
    public void setUp() {

        mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        module.addDeserializer(KeyStoreFileDTO.class, new ReissueWithCSRDeSerializer());
        mapper.registerModule(module);

        keyStoreFileDTO.setChain(true);
        keyStoreFileDTO.setFormat(KeyStoreType.PKCS12);
        keyStoreFileDTO.setName("TestEntity");
        keyStoreFileDTO.setPassword("secret");
        keyStoreFileDTO.setData("csr");
        keyStoreFileDTO.setRevocationReason(RevocationReason.PRIVILEGE_WITHDRAWN);
    }

    /**
     * Method to test CAReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testReissueWithCSRDeSerializer() throws JsonProcessingException, IOException {

    	final String inputJsonKeyStoreFileDTO = "{\"name\":\"TestEntity\",\"chain\":true,\"format\":\"PKCS12\",\"password\":\"secret\",\"revocationReason\":\"PRIVILEGE_WITHDRAWN\",\"data\":\"csr\"}"; 
    	final KeyStoreFileDTO expectedKeyStoreFileDTO = mapper.readValue(inputJsonKeyStoreFileDTO, KeyStoreFileDTO.class);
        assertEquals(expectedKeyStoreFileDTO.getName(), keyStoreFileDTO.getName());
        assertEquals(expectedKeyStoreFileDTO.getFormat(), keyStoreFileDTO.getFormat());
        assertEquals(expectedKeyStoreFileDTO.getPassword(), keyStoreFileDTO.getPassword());
        assertEquals(expectedKeyStoreFileDTO.getRevocationReason(), keyStoreFileDTO.getRevocationReason());
    }

    /**
     * Method to test CAReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testReissueWithCSRDeSerializer_With_Int_RevocationReason() throws JsonProcessingException, IOException {

        final String inputJsonKeyStoreFileDTO = "{\"name\":\"TestEntity\",\"chain\":true,\"format\":\"PKCS12\",\"password\":\"secret\",\"revocationReason\":\"9\",\"data\":\"csr\"}";
        final KeyStoreFileDTO expectedKeyStoreFileDTO = mapper.readValue(inputJsonKeyStoreFileDTO, KeyStoreFileDTO.class);
        assertEquals(expectedKeyStoreFileDTO.getName(), keyStoreFileDTO.getName());
        assertEquals(expectedKeyStoreFileDTO.getFormat(), keyStoreFileDTO.getFormat());
        assertEquals(expectedKeyStoreFileDTO.getPassword(), keyStoreFileDTO.getPassword());
        assertEquals(expectedKeyStoreFileDTO.getRevocationReason(), keyStoreFileDTO.getRevocationReason());
    }

    /**
     * Method to test CAReissuedeSerialize
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testReissueWithCSRDeSerializer_With_Invalid_RevocationReason() throws JsonProcessingException, IOException {
        final String inputJsonKeyStoreFileDTO = "{\"name\":\"TestEntity\",\"chain\":true,\"format\":\"PKCS12\",\"password\":\"secret\",\"revocationReason\":\"20\",\"data\":\"csr\"}";
        final KeyStoreFileDTO expectedKeyStoreFileDTO = mapper.readValue(inputJsonKeyStoreFileDTO, KeyStoreFileDTO.class);
        assertEquals(expectedKeyStoreFileDTO.getName(), keyStoreFileDTO.getName());
        assertEquals(expectedKeyStoreFileDTO.getFormat(), keyStoreFileDTO.getFormat());
        assertEquals(expectedKeyStoreFileDTO.getPassword(), keyStoreFileDTO.getPassword());
        assertNull(expectedKeyStoreFileDTO.getRevocationReason());

    }

}
