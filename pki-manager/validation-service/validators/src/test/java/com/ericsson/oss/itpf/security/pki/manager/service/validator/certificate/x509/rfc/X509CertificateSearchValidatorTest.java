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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.io.FileNotFoundException;
import java.security.cert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.X509CertificateSearchValidator;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateSearchValidatorTest {

    @InjectMocks
    X509CertificateSearchValidator basicValidation;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    Logger logger;

    private static DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();

    @Test
    public void validate() throws CertificateException, FileNotFoundException, CRLException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        basicValidation.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test(expected = CertificateAlreadyExistsException.class)
    public void testValidate_Exception() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        String caName = "RootCA";
        Mockito.when(caCertificatePersistenceHelper.getCertificatesCount(caName, Long.toHexString(certificateToValidate.getSerialNumber().longValue()))).thenReturn(2);
        basicValidation.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));

    }

}
