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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidOperationException;

@RunWith(MockitoJUnitRunner.class)
public class ImportCertificateCAValidatorTest {

    @InjectMocks
    private ImportCertificateCAValidator importCertificateCAValidator;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test(expected = InvalidCAException.class)
    public void testValidateInvalidCAException() {
        String caName = "caName";
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setStatus(CAStatus.INACTIVE);
        Mockito.when(certificatePersistenceHelper.getCA(caName)).thenReturn(certificateAuthorityData);
        importCertificateCAValidator.validate(caName);
    }

    @Test(expected = InvalidOperationException.class)
    public void testValidateInvalidOperationException() {
        String caName = "caName";
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setStatus(CAStatus.INACTIVE);
        Mockito.when(certificatePersistenceHelper.getCA(caName)).thenReturn(certificateAuthorityData);
        importCertificateCAValidator.validate(caName);
    }

}
