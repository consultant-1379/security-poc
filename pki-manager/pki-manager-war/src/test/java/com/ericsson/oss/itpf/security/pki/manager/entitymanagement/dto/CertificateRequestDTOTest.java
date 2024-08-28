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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

@RunWith(MockitoJUnitRunner.class)
public class CertificateRequestDTOTest {

    CertificateRequestDTO certificateRequestDTO;
    CertificateRequestDTO expectedCertificateRequestDTO;

    @Before
    public void setUP() {
        certificateRequestDTO = getEndEntityCertificateRequestDTOWithOutChain();
        expectedCertificateRequestDTO = getEndEntityCertificateRequestDTOWithOutChain();
    }

    @Test
    public void testEqual() {
        expectedCertificateRequestDTO = getEndEntityCertificateRequestDTOWithOutChain();
        certificateRequestDTO.hashCode();
        certificateRequestDTO.toString();

        assertTrue(certificateRequestDTO.equals(certificateRequestDTO));
        assertTrue(certificateRequestDTO.equals(expectedCertificateRequestDTO));
        assertFalse(certificateRequestDTO.equals(null));
        assertFalse(certificateRequestDTO.equals(new ProfilesDTO()));

        certificateRequestDTO.setChain(true);
        assertFalse(certificateRequestDTO.equals(expectedCertificateRequestDTO));

        certificateRequestDTO.setChain(false);
        certificateRequestDTO.setFormat(KeyStoreType.PEM);
        assertFalse(certificateRequestDTO.equals(expectedCertificateRequestDTO));

    }

    @Test
    public void testNotEqualNoName() {
        certificateRequestDTO.setFormat(KeyStoreType.JKS);
        expectedCertificateRequestDTO = getEndEntityCertificateRequestDTOWithOutChain();
        expectedCertificateRequestDTO.setName("Test");
        certificateRequestDTO.equals(expectedCertificateRequestDTO);
        expectedCertificateRequestDTO.setName("Entity");
        certificateRequestDTO.setName(null);
        assertFalse(certificateRequestDTO.equals(expectedCertificateRequestDTO));
        certificateRequestDTO.setName("Entity");
    }

    @Test
    public void testNotEqualNoPassword() {

        expectedCertificateRequestDTO.setPassword("Test");
        certificateRequestDTO.equals(expectedCertificateRequestDTO);
        expectedCertificateRequestDTO.setPassword("secure");
        certificateRequestDTO.setPassword(null);
        assertFalse(certificateRequestDTO.equals(expectedCertificateRequestDTO));
        certificateRequestDTO.setPassword("secure");
    }

    @Test
    public void testNotEqualDiffKeyFormat() {

        expectedCertificateRequestDTO.setRekey(true);
        assertFalse(certificateRequestDTO.equals(expectedCertificateRequestDTO));
        expectedCertificateRequestDTO.setRekey(false);
    }

    @Test
    public void testNotEqualDiffType() {

        expectedCertificateRequestDTO.setType(EntityType.CA_ENTITY);
        assertFalse(certificateRequestDTO.equals(expectedCertificateRequestDTO));
    }

    private CertificateRequestDTO getEndEntityCertificateRequestDTOWithOutChain() {
        final CertificateRequestDTO certificateRequestDTO = new CertificateRequestDTO();
        certificateRequestDTO.setName("Entity");
        certificateRequestDTO.setChain(false);
        certificateRequestDTO.setType(EntityType.ENTITY);
        certificateRequestDTO.setFormat(KeyStoreType.JKS);
        certificateRequestDTO.setPassword("secure");
        return certificateRequestDTO;
    }
}
