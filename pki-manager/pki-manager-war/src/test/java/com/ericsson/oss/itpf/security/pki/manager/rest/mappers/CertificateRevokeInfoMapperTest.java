/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.rest.mappers;

import static org.junit.Assert.assertNotNull;

import javax.ws.rs.core.Response.Status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.CertificateRevocationInfoDTO;

@RunWith(MockitoJUnitRunner.class)
public class CertificateRevokeInfoMapperTest {
    @InjectMocks
    CertificateRevocationInfoMapper certificateRevokeInfoMapper;

    CertificateRevocationInfoDTO certificateRevokeDTO;

    @Before
    public void setUp() throws Exception {
        certificateRevokeDTO = new CertificateRevocationInfoDTO();
        certificateRevokeDTO.setSerialNumber("5846e6e7c5d3c7a2");
        certificateRevokeDTO.setIssuer("CN=ARJ_Root");
        certificateRevokeDTO.setSubject("CN=ARJ_Sub_21");
        certificateRevokeDTO.setRevocationReason(RevocationReason.UNSPECIFIED);
    }

    @Test
    public void TestGetDnBasedCertificateIdentifier() {

        assertNotNull(certificateRevokeInfoMapper.getDnBasedCertificateIdentifier(certificateRevokeDTO));
    }

    @Test
    public void TestGetRevokeStatusDTO() {

        String message = "Certificate has been revoked.";
        assertNotNull(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevokeDTO, message, Status.OK.getStatusCode(), "30002"));
    }
}
