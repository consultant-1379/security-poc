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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration;

import static org.mockito.Mockito.when;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.AlgorithmDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SignatureAlgorithmValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(SignatureAlgorithmValidator.class);

    @InjectMocks
    SignatureAlgorithmValidator signatureAlgorithmValidator;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    //    @Test
    /*
     * public void testSignatureAlgorithm_Valid() throws DatatypeConfigurationException { CertificateProfileSetUpData certificateProfileSetUpData =
     * new CertificateProfileSetUpData();
     *
     * when(algorithmPersistenceHandler.getAlgorithmByNameAndType( certificateProfileSetUpData .getCertificateProfile().getSignatureAlgorithm(),
     * AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn( certificateProfileSetUpData.getAlgorithmData()); signatureAlgorithmValidator
     * .validateSignatureAlgorithm(certificateProfileSetUpData .getCertificateProfile().getSignatureAlgorithm()); }
     */

    @Test(expected = AlgorithmNotFoundException.class)
    public void testSignatureAlgorithm_InValidAlgorithmData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpData = new CertificateProfileSetUpData();

        when(
                algorithmPersistenceHandler.getAlgorithmByNameAndType(certificateProfileSetUpData.getCertificateProfile().getSignatureAlgorithm(),
                        AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(null);
        signatureAlgorithmValidator.validate(certificateProfileSetUpData.getCertificateProfile().getSignatureAlgorithm());
    }

    @Test
    public void testSignatureAlgorithm_ValidAlgorithmData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpData = new CertificateProfileSetUpData();
        final AlgorithmDataSetUp AlgorithmDataSetUp = new AlgorithmDataSetUp();
        when(
                algorithmPersistenceHandler.getAlgorithmByNameAndType(certificateProfileSetUpData.getCertificateProfile().getSignatureAlgorithm(),
                        AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(AlgorithmDataSetUp.getSupportedSignatureAlgorithm());
        signatureAlgorithmValidator.validate(certificateProfileSetUpData.getCertificateProfile().getSignatureAlgorithm());
        Mockito.verify(algorithmPersistenceHandler).getAlgorithmByNameAndType(
                certificateProfileSetUpData.getCertificateProfile().getSignatureAlgorithm(), AlgorithmType.SIGNATURE_ALGORITHM);
    }
}
