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
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.helper.AlgorithmLoader;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateSignatureAlgorithmValidatorTest {

    @InjectMocks
    X509CertificateSignatureAlgorithmValidator x509CertificateSignatureAlgorithmValidator;

    @Mock
    Logger logger;

    @Mock
    AlgorithmLoader algorithmLoader;

    Algorithm algorithm = new Algorithm();

    List<Algorithm> algorithms = new ArrayList<Algorithm>();

    private static String caName = "caName";

    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidate() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        final CACertificateValidationInfo caCertificateValidationInfo = certificateBase.getRootCACertificateInfo(certificateToValidate);

        algorithm.setName("SHA256withRSA");
        algorithms.add(algorithm);
        Mockito.when(algorithmLoader.getSupportedAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(algorithms);

        x509CertificateSignatureAlgorithmValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).debug("Validating X509Certificate SignatureAlgorithm for CA and Algorithm is {} ", caName, certificateToValidate.getSigAlgName());
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidate_exception() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        final CACertificateValidationInfo caCertificateValidationInfo = certificateBase.getRootCACertificateInfo(certificateToValidate);

        certificateToValidate.getSigAlgName();

        algorithm.setName("SHA256withRSA");
        Mockito.when(algorithmLoader.getSupportedAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(algorithms);

        x509CertificateSignatureAlgorithmValidator.validate(caCertificateValidationInfo);
        Mockito.verify(logger).error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, " for CA {} ", caName, " Algorithm present in the certificate is {} ", certificateToValidate.getSigAlgName());

    }
}
