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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard;

import static org.mockito.Mockito.verify;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmCategory;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link KeyIdentifierValidator}
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorityKeyIdentifierValidatorTest {
    @Mock
    private Logger logger;

    @InjectMocks
    private AuthorityKeyIdentifierValidator authorityKeyIdentifierValidator;

    @InjectMocks
    private SubjectKeyIdentifierValidator subjectKeyIdentifierValidator;

    @Mock
    PersistenceManager persistenceManager;

    private Algorithm algorithm;
    private CertificateProfile certificateProfile;
    private AuthorityKeyIdentifier authorityKeyIdentifier;
    private SubjectKeyIdentifier subjectKeyIdentifier;
    private CertificateProfileSetUpData certificateProfileSetUpToTest;
    private CertificateProfileData certificateProfileData;

    private static final String ALGORITHM_NAME = "name";

    private static final String ALGORITHM_SUPPORTED = "supported";
    private static final String ALGORITHM_CATEGORIES = "categories";

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();

        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        algorithm = certificateProfileSetUpToTest.getCertificateProfile().getSignatureAlgorithm();
        for (final CertificateExtension certificateExtension : certificateProfile.getCertificateExtensions().getCertificateExtensions()) {
            if (certificateExtension != null) {
                if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER.getName())) {
                    authorityKeyIdentifier = (AuthorityKeyIdentifier) certificateExtension;
                } else if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER.getName())) {
                    subjectKeyIdentifier = (SubjectKeyIdentifier) certificateExtension;
                }
            }
        }
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidateAuthorithyKeyIdentifier() {

        authorityKeyIdentifierValidator.validate(authorityKeyIdentifier, true, "TestIssuer");
        verify(logger).debug("Validating AuthorityKeyIdentifier in CertificateProfile{}", authorityKeyIdentifier);
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test(expected = InvalidAuthorityKeyIdentifierExtension.class)
    public void testValidateAuthorithyKeyIdentifierIsCriticalException() {
        authorityKeyIdentifier.setCritical(true);
        authorityKeyIdentifierValidator.validate(authorityKeyIdentifier, false, "TestIssuer");
        verify(logger).debug("Validating AuthorityKeyIdentifier in CertificateProfile{}", authorityKeyIdentifier);
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test(expected = InvalidAuthorityKeyIdentifierExtension.class)
    public void testValidateAuthorithyKeyIdentifierAsSubjectkeyIdentifierEx() {
        authorityKeyIdentifier.setSubjectkeyIdentifier(certificateProfileSetUpToTest.getSubjectKeyIdentifier());
        authorityKeyIdentifierValidator.validate(authorityKeyIdentifier, false, "TestIssuer");
        verify(logger).debug("Validating AuthorityKeyIdentifier in CertificateProfile{}", authorityKeyIdentifier);
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test(expected = InvalidAuthorityKeyIdentifierExtension.class)
    public void testValidateAuthorithyKeyIdentifierTypeAsNullEx() {
        authorityKeyIdentifier.setType(null);
        authorityKeyIdentifierValidator.validate(authorityKeyIdentifier, false, "TestIssuer");
        verify(logger).debug("Validating AuthorityKeyIdentifier in CertificateProfile{}", authorityKeyIdentifier);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidateSubjectKeyIdentifier() {
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.KEY_IDENTIFIER.getId());

        final AlgorithmData signatureAlgorithm = certificateProfileData.getSignatureAlgorithm();

        final Map<String, Object> input = new HashMap<String, Object>();
        algorithm = certificateProfile.getSignatureAlgorithm();

        input.put(ALGORITHM_NAME, algorithm.getName());
        input.put(ALGORITHM_CATEGORIES, categories);
        input.put(ALGORITHM_SUPPORTED, Boolean.TRUE);

        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(signatureAlgorithm);
        subjectKeyIdentifierValidator.validate(subjectKeyIdentifier, true, "TestIssuer");
        verify(logger).debug("Validating SubjectKeyIdentifier in CertificateProfile{}", subjectKeyIdentifier);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateSubjectKeyIdentifierEx() {
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.KEY_IDENTIFIER.getId());

        final Map<String, Object> input = new HashMap<String, Object>();
        algorithm = certificateProfile.getSignatureAlgorithm();

        input.put(ALGORITHM_NAME, algorithm.getName());
        input.put(ALGORITHM_CATEGORIES, categories);
        input.put(ALGORITHM_SUPPORTED, Boolean.TRUE);

        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(null);
        subjectKeyIdentifierValidator.validate(subjectKeyIdentifier, true, "TestIssuer");
        verify(logger).debug("Validating SubjectKeyIdentifier in CertificateProfile{}", subjectKeyIdentifier);
    }

    /**
     * Method to test validate method in negative scenario. When keyIdentifier is set to null for SubjectKeyIdentifier
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateSubjectKeyIdentifierAsNull() {
        subjectKeyIdentifier.setKeyIdentifier(null);
        subjectKeyIdentifierValidator.validate(subjectKeyIdentifier, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When algorithm in keyIdentifier is set to null for SubjectKeyIdentifier
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateSubjectKeyIdentifierWhenAlgorithmAsNull() {
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setAlgorithm(null);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        subjectKeyIdentifierValidator.validate(subjectKeyIdentifier, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When critical is set to true for SubjectKeyIdentifier
     */
    @Test(expected = InvalidSubjectKeyIdentifierExtension.class)
    public void testValidateSubjectKeyIdentifierWithCriticalTrue() {
        subjectKeyIdentifier.setCritical(true);
        subjectKeyIdentifierValidator.validate(subjectKeyIdentifier, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When IssuerSubjectAndSerialNumber value is null
     */
    @Test(expected = InvalidAuthorityKeyIdentifierExtension.class)
    public void testValidateIssuerSubjectAndSerialNumberAsNull() {
        authorityKeyIdentifier.setIssuerSubjectAndSerialNumber(new Certificate());
        authorityKeyIdentifierValidator.validate(authorityKeyIdentifier, false, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When AuthorityKeyidentifier value is null
     */
    @Test
    public void testAuthorityKeyidentifierAsNull() {
        authorityKeyIdentifier = null;
        authorityKeyIdentifierValidator.validate(authorityKeyIdentifier, false, "TestIssuer");
        verify(logger).debug("Validating AuthorityKeyIdentifier in CertificateProfile{}", authorityKeyIdentifier);
    }
}
