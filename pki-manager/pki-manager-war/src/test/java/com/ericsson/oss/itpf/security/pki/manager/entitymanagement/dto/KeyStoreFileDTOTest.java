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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import static org.junit.Assert.assertFalse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

/**
 * This class will test KeyStoreFileDTOTest
 * 
 * @author tcsrav
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class KeyStoreFileDTOTest {

    KeyStoreFileDTO keyStoreFileDTO;
    KeyStoreFileDTO expectedKeyStoreFileDTO;

    @Before
    public void setUP() {
        keyStoreFileDTO = getKeyStoreFileDTO();
        expectedKeyStoreFileDTO = getKeyStoreFileDTO();
    }

    /**
     * Method to test Positive scenario
     * 
     * 
     */
    @Test
    public void testEquals() {

        keyStoreFileDTO.hashCode();
        keyStoreFileDTO.toString();
        keyStoreFileDTO.equals(null);
        keyStoreFileDTO.equals(keyStoreFileDTO);
        keyStoreFileDTO.equals(expectedKeyStoreFileDTO);

        assertFalse(keyStoreFileDTO.equals(new ProfilesDTO()));

        keyStoreFileDTO.setChain(false);
        keyStoreFileDTO.equals(expectedKeyStoreFileDTO);
        keyStoreFileDTO.setChain(true);
        keyStoreFileDTO.setData("testData");

        assertFalse(keyStoreFileDTO.equals(expectedKeyStoreFileDTO));

        keyStoreFileDTO.setData(null);
        assertFalse(keyStoreFileDTO.equals(expectedKeyStoreFileDTO));
        keyStoreFileDTO.setData(expectedKeyStoreFileDTO.getData());
    }

    /**
     * Method to test Negative scenario
     * 
     */
    @Test
    public void testNotEqualsNoName() {

        keyStoreFileDTO.setFormat(KeyStoreType.PEM);
        keyStoreFileDTO.equals(expectedKeyStoreFileDTO);
        keyStoreFileDTO.setFormat(KeyStoreType.JKS);
        keyStoreFileDTO.setName("Test");
        keyStoreFileDTO.equals(expectedKeyStoreFileDTO);
        keyStoreFileDTO.setName(null);

        assertFalse(keyStoreFileDTO.equals(expectedKeyStoreFileDTO));

        keyStoreFileDTO.setName("entity");
        keyStoreFileDTO.setPassword("Test");
        keyStoreFileDTO.equals(expectedKeyStoreFileDTO);
        keyStoreFileDTO.setPassword(null);

        assertFalse(keyStoreFileDTO.equals(expectedKeyStoreFileDTO));
    }

    private KeyStoreFileDTO getKeyStoreFileDTO() {
        final KeyStoreFileDTO keyStoreFileDTO = new KeyStoreFileDTO();
        keyStoreFileDTO.setChain(true);
        keyStoreFileDTO
                .setData("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0NCk1JSUN3ekNDQWFzQ0FRQXdaakVMTUFrR0ExVUVCaE1DU1U0eEVqQVFCZ05WQkFnTUNWUmxiR0Z1WjJGdVlURVQNCk1CRUdBMVVFQnd3S1NIbGtaWEppWVdKaFpERU1NQW9HQTFVRUNnd0RWRU5UTVJFd0R3WURWUVFMREFoRlVrbEQNClUxTlBUakVOTUFzR0ExVUVBd3dFVWtGcVlUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0MNCmdnRUJBTjZxNVJBVFA2TkhoSjM1Si96WDN0R0I3VW1JMXlUUW9lWDBqOU1LN0VqUzBkajJDb3hiOWRwa1ZTcVQNCnZFOEFmSndtaFIzVTR2c1ZjSytGNjExYTcrZTdCdUJUSi9lRDF5Sk1aQ2NwaXl1cUZoQ0JlaHJYTGFtSXN2TkENCktOeEd6dlJxdzZGK3FvY09nNWxGaHIyNnAyUi9VbU9ZUlo4aTIwb0pTb3FRcVdhdEVVRVZmaTlqUmxoUHE2bWkNCmFDUmFGc3dmWjZtQXI3eHh0Vnhsb1A1ZVNRS1pGbGhHaTVETEx0RXFCZVJQV2l6SC9TekJTS1BhZFpJTVdlNWUNCnN1a2lYYXV6VEc1bFBKWWtRakZEN3BjY2o4U3R6UytzWlBtdTMzYndxVExJSWd0UkxIeUhPWGd4VDNvMmhNSEsNCkNrVDhZZ3NVZThnTTFyUnF1MGJXdHNGRGtyRUNBd0VBQWFBWU1CWUdDU3FHU0liM0RRRUpCekVKREFkMFpYTjANCk1USXpNQTBHQ1NxR1NJYjNEUUVCQlFVQUE0SUJBUURWZXF0VlBKaTNqQU9YYWRqTTlZRlVVTGNxQks4ODNtWG8NCkloOGRBaDU2U1RWVXBvMWErREtmT1FVRGhIUWsrL01OVE9nd3lVSFl2U2djQ1NaTW1XSHhjL0h5eDh0WjhmcWcNClQySEF0dmhYeU9nZjJaZCtxQWIza0t2bm5HdVJGNkNCb1RqOHFNRThCbWRkMTkrNnppNUVvUGdEUUluR3FPUTQNCnpKcHBzNE82QkJicG8ydmFSMWJCMlRSSDcvNTJkTisrUFkzK0tyQ2x0MmprcXJwSW5ISDBNR05vTitmSXMvb3YNCmYyU2NKRDNQWGVxVWZwbXhuSkp1elBraEZhRFpNNEozR2VFZExOdEluN3UxMWFiZW5URHhOY0Q4dHRVSWRMMlQNCjdWQUMzRVdSUU1ZTWdSTnM5V1ZqKzJzSnFNc1UyaDE1QjZRWjVOeU9TbUo5SnFKT0JRNHQNCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQ==");
        keyStoreFileDTO.setName("entity");
        keyStoreFileDTO.setFormat(KeyStoreType.JKS);
        keyStoreFileDTO.setPassword("entity");
        return keyStoreFileDTO;
    }

}
