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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.RevocationRequestData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.modelmapper.RevocationRequestModelMapper;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.validator.RevocationRequestValidator;
import com.ericsson.oss.itpf.security.pki.core.revocation.helper.RevocationPersistenceHelper;

@RunWith(MockitoJUnitRunner.class)
public class RevocationManagerTest extends BaseTest {

    @InjectMocks
    RevocationManager revocationManager;

    @Mock
    Logger logger;

    @Mock
    RevocationPersistenceHelper revocationPersistenceHelper;

    @Mock
    RevocationRequestModelMapper revocationRequestModelMapper;

    @Mock
    RevocationRequestValidator revocationRequestValidator;

    @Mock
    private SystemRecorder systemRecorder;

    private static Certificate certificate;
    private static CertificateData certificateData;
    private static RevocationRequestData revocationRequestData;
    private static List<Certificate> certificateList = new ArrayList<Certificate>();

    private static RevocationRequest revocationRequest;

    /**
     * Method to test {@link RevocationRequest} API model to {@link RevocationRequestData} JPA object
     * 
     */

    @Before
    public void setUp() {

        certificate = prepareCertificate(111, "1001");
        certificateList.add(certificate);
        certificateData = prepareCertificateData(111, "1001");

        revocationRequest = new RevocationRequest();
        revocationRequest.setCertificatesToBeRevoked(certificateList);
        revocationRequest.setCaEntity(prepareCertificateAuthority(10101L, "ENM_CA"));
        revocationRequestData = prepareRevocationRequestDataWithCaEntity();
        revocationRequestData.getCertificatesToRevoke().add(certificateData);

    }

    @Test
    public void testRevokeCertificateByRevocationRequest() {

        Mockito.when(revocationRequestModelMapper.fromAPIModel(revocationRequest)).thenReturn(revocationRequestData);
        revocationManager.revokeCertificateByRevocationRequest(revocationRequest);
    }
}
