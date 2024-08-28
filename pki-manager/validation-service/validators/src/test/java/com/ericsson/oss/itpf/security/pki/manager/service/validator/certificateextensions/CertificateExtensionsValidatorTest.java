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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidatorFactory;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionsValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link CertificateExtensionsValidator}
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateExtensionsValidatorTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateExtensionsValidator.class);

    @InjectMocks
    private CertificateExtensionsValidator certificateExtensionsValidator;

    @Mock
    private CertificateExtensionValidatorFactory certificateExtensionValidatorFactory;

    @Mock
    private CertificateExtensionValidator certificateExtensionValidator;

    private CertificateProfile certificateProfile;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();

        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.BASIC_CONSTRAINTS)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.AUTHORITY_INFORMATION_ACCESS)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.CRL_DISTRIBUTION_POINTS)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.EXTENDED_KEY_USAGE)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.KEY_USAGE)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.SUBJECT_ALT_NAME)).thenReturn(certificateExtensionValidator);
        when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER)).thenReturn(certificateExtensionValidator);
    }

    private void notFillCertificateExtension(final CertificateExtensionType certificateExtensionType) {
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        for (final CertificateExtension certificateExtension : certificateProfile.getCertificateExtensions().getCertificateExtensions()) {
            if (certificateExtension != null) {
                if (!certificateExtension.getClass().getSimpleName().equals(certificateExtensionType.getName())) {
                    certificateExtensionList.add(certificateExtension);
                }
            }
        }
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        certificateProfile.setCertificateExtensions(certificateExtensions);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        certificateExtensionsValidator.validate(certificateProfile);
    }

    /**
     * Method to test validate method in negative scenario. When CertificateExtensions is set to null in CertificateProfile
     */
    @Test(expected = CertificateExtensionException.class)
    public void testValidateWithExtensionsNull() {
        certificateProfile.setCertificateExtensions(null);
        certificateExtensionsValidator.validate(certificateProfile);
    }

    /**
     * Method to test validate method in negative scenario. When BasicConstraints extension is not specified for CA entity
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateWithoutBasicConstraints() {
        notFillCertificateExtension(CertificateExtensionType.BASIC_CONSTRAINTS);
        certificateExtensionsValidator.validate(certificateProfile);
    }

    /**
     * Method to test validate method in negative scenario. When SubjectKeyIdentifier extension is not specified for CA entity
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateWithoutSubjectKeyIdenfier() {
        notFillCertificateExtension(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER);
        certificateExtensionsValidator.validate(certificateProfile);
    }

    /**
     * Method to test validate method in negative scenario. When KeyUsage extension is not specified for CA entity
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateWithoutKeyUsage() {
        notFillCertificateExtension(CertificateExtensionType.KEY_USAGE);
        certificateExtensionsValidator.validate(certificateProfile);
    }
}
