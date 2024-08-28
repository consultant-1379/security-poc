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
package com.ericsson.oss.itpf.security.pki.core.revocation.helper;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.RevocationRequestData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.util.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;

@RunWith(MockitoJUnitRunner.class)
public class RevocationPersistenceHelperTest extends BaseTest {

    @InjectMocks
    RevocationPersistenceHelper revocationPersisitenceHelper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    private CertificateData certificateData;
    private RevocationRequestData revocationRequestData;
    private Set<CertificateData> certificates = new HashSet<CertificateData>();;

    @Before
    public void setUp() {

        certificateData = prepareCertificateData(101, "123");
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificates.add(certificateData);
        revocationRequestData = prepareRevocationRequestDataWithCaEntity();
    }

    @Test
    public void testUpdateCertificateStatusForRevocationRequest() {
        Mockito.doNothing().when(persistenceManager).updateCertificateStatus(certificateData.getId(), CertificateStatus.INACTIVE.getId());
        revocationPersisitenceHelper.updateCertificateStatusForRevocationRequest(revocationRequestData);
        Mockito.verify(persistenceManager).updateEntity(revocationRequestData);
    }

    @Test
    public void testStoreRevocationRequest() {
        Mockito.doNothing().when(persistenceManager).createEntity(revocationRequestData);

        revocationPersisitenceHelper.storeRevocationRequest(revocationRequestData);

    }

    @Test
    public void testUpdateRevocationRequestStatus() {
        Mockito.when(persistenceManager.updateEntity(revocationRequestData)).thenReturn(revocationRequestData);

        revocationPersisitenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.NEW);
        Mockito.verify(persistenceManager).updateEntity(revocationRequestData);

    }

    @Test(expected = RevocationServiceException.class)
    public void testUpdateCertificateStatus_Persistenceexception() {

        Mockito.when(persistenceManager.updateEntity(revocationRequestData)).thenThrow(new PersistenceException(ErrorMessages.INTERNAL_ERROR));
        revocationPersisitenceHelper.updateCertificateStatusForRevocationRequest(revocationRequestData);
    }

    @Test(expected = RevocationServiceException.class)
    public void testStoreRevocationRequest_PersistenceException() {

        Mockito.doThrow(new PersistenceException(ErrorMessages.INTERNAL_ERROR)).when(persistenceManager).createEntity(revocationRequestData);
        revocationPersisitenceHelper.storeRevocationRequest(revocationRequestData);

    }

    @Test(expected = RevocationServiceException.class)
    public void testUpdateRevocationRequestStatus_PersistenceException() {

        Mockito.when(persistenceManager.updateEntity(revocationRequestData)).thenThrow(new PersistenceException(ErrorMessages.INTERNAL_ERROR));
        revocationPersisitenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.NEW);
    }
}
