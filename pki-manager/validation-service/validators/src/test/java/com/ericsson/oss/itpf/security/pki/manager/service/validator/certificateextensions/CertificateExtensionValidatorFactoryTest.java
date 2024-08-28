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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidatorFactory;

@RunWith(MockitoJUnitRunner.class)
public class CertificateExtensionValidatorFactoryTest {

    @InjectMocks
    private CertificateExtensionValidatorFactory certificateExtensionValidatorFactory;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.AUTHORITY_INFORMATION_ACCESS)
    private CertificateExtensionValidator authorityInformationAccessValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER)
    private CertificateExtensionValidator authorityKeyIdentifierValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.BASIC_CONSTRAINTS)
    private CertificateExtensionValidator basicConstraintsValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.CRL_DISTRIBUTION_POINTS)
    private CertificateExtensionValidator cRLDistributionPointValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.EXTENDED_KEY_USAGE)
    private CertificateExtensionValidator extendedKeyUsageValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.KEY_USAGE)
    private CertificateExtensionValidator keyUsageValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER)
    private CertificateExtensionValidator subjectKeyIdentifierValidator;

    @Mock
    @CertificateExtensionsQualifier(CertificateExtensionType.SUBJECT_ALT_NAME)
    private CertificateExtensionValidator subjectAltNameExtensionValidator;

    /**
     * Method to test getCertificateExtensionValidator method to get authorityInformationAccessValidator.
     */
    @Test
    public void testGetAuthorityInformationAccessValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.AUTHORITY_INFORMATION_ACCESS), authorityInformationAccessValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get authorityKeyIdentifierValidator.
     */
    @Test
    public void testGetAuthorityKeyIdentifierValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER), authorityKeyIdentifierValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get basicConstraintsValidator.
     */
    @Test
    public void testGetBasicConstraintValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.BASIC_CONSTRAINTS), basicConstraintsValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get cRLDistributionPointValidator.
     */
    @Test
    public void testGetCRLDistributionValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.CRL_DISTRIBUTION_POINTS), cRLDistributionPointValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get extendedKeyUsageValidator.
     */
    @Test
    public void testGetExtendedKeyUsageValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.EXTENDED_KEY_USAGE), extendedKeyUsageValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get keyUsageValidator.
     */
    @Test
    public void testGetKeyUsageValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.KEY_USAGE), keyUsageValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get subjectAltNameExtensionValidator.
     */
    @Test
    public void testGetSubjectAltNameValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.SUBJECT_ALT_NAME), subjectAltNameExtensionValidator);
    }

    /**
     * Method to test getCertificateExtensionValidator method to get subjectKeyIdentifierValidator.
     */
    @Test
    public void testGetSubjectKeyIdentifierValidator() {
        assertEquals(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER), subjectKeyIdentifierValidator);
    }
}
