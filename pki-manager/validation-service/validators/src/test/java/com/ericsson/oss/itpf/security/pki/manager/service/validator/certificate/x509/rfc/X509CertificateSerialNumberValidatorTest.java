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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateSerialNumberValidatorTest {

    @InjectMocks
    X509CertificateSerialNumberValidator certificateSerialNumberValidator;

    @Mock
    X509Certificate certificateToValidate;

    @Mock
    Logger logger;

    @Mock
    CertificateBase certificateBase;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");

        CACertificateValidationInfo caCertificateValidationInfo = certificateBase.getRootCACertificateInfo(certificateToValidate);
        certificateSerialNumberValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).debug("Validating X509Certificate SerialNumber for CA {} ", caCertificateValidationInfo.getCaName(), "{} ", certificateToValidate.getSerialNumber());

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidate_Exception() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10022.crt");
        CACertificateValidationInfo caCertificateValidationInfo = certificateBase.getRootCACertificateInfo(certificateToValidate);
        certificateSerialNumberValidator.validate(caCertificateValidationInfo);
        Mockito.when(certificateBase.getX509Certificate("ENM_RootCA10022.crt").getSerialNumber()).thenReturn(certificateToValidate.getSerialNumber());

        Mockito.when(certificateBase.getX509Certificate("ENM_RootCA10022.crt").getSerialNumber()).thenReturn(certificateToValidate.getSerialNumber().negate());

        certificateSerialNumberValidator.validate(caCertificateValidationInfo);
        Mockito.verify(logger).error(ErrorMessages.SERIAL_NUMBER_VALIDATION_FAILED + " for CA {} ", caCertificateValidationInfo.getCaName(), "and Serial Number is {} ", certificateToValidate.getSerialNumber());
        Mockito.verify(logger).error("Serial number validation failed");

    }

}
