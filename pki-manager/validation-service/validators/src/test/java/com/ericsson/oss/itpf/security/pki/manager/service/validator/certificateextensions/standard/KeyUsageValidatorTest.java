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

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
//import com.ericsson.oss.itpf.security.pki.manager.common.persistence.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link KeyUsageValidator}
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class KeyUsageValidatorTest {
    @Mock
    private Logger logger;

    @InjectMocks
    private KeyUsageValidator keyUsageValidator;

    @InjectMocks
    private ExtendedKeyUsageValidator extendedKeyUsageValidator;

    private CertificateProfile certificateProfile;
    private KeyUsage keyUsage;
    private ExtendedKeyUsage extendedKeyUsage;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        for (final CertificateExtension certificateExtension : certificateProfile.getCertificateExtensions().getCertificateExtensions()) {
            if (certificateExtension != null) {
                if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.KEY_USAGE.getName())) {
                    keyUsage = (KeyUsage) certificateExtension;
                } else if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.EXTENDED_KEY_USAGE.getName())) {
                    extendedKeyUsage = (ExtendedKeyUsage) certificateExtension;
                }
            }
        }
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidateKeyUsage() {
        keyUsageValidator.validate(keyUsage, true, "TestIssuer");
        verify(logger).debug("Validating KeyUsage in CertificateProfile{}", keyUsage);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidateExtendedKeyUsage() {
        extendedKeyUsageValidator.validate(extendedKeyUsage, true, "TestIssuer");
        verify(logger).debug("Validating ExtendedKeyUsage in CertificateProfile{}", extendedKeyUsage);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidateKeyUsageForNonCAEntity() {
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsageValidator.validate(keyUsage, false, "TestIssuer");
        verify(logger).debug("Validating KeyUsage in CertificateProfile{}", keyUsage);
    }

    /**
     * Method to test validate method in negative scenario. When no keyUsageType is specified
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateKeyUsageWIthKeyUsageTypeNull() {
        keyUsage.setSupportedKeyUsageTypes(null);
        keyUsageValidator.validate(keyUsage, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When keyUsageType with no KeyCertSign is specified for CAEntity
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateKeyUsageWIthKeyUsageTypeWithoutKeyCertSign() {
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsageValidator.validate(keyUsage, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When keyUsageType with no CRLSign is specified for CAEntity
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateKeyUsageWIthKeyUsageTypeWithoutCRLSign() {
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsageValidator.validate(keyUsage, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When keyUsageType with KeyCertSign is specified for EndEntity
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateKeyUsageForNonCAEntityWithKeyCertSign() {
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsageValidator.validate(keyUsage, false, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When keyUsageType with CRLSign is specified for EndEntity
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateKeyUsageForNonCAEntityWithCRLSign() {
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsageValidator.validate(keyUsage, false, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When no KeyPurposeIds given.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateExtendedKeyUsageWithKeyPurposeIdsNull() {
        extendedKeyUsage.setSupportedKeyPurposeIds(null);
        extendedKeyUsageValidator.validate(extendedKeyUsage, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When critical is set to false in ExtendedKeyUsage
     */
    @Test(expected = InvalidExtendedKeyUsageExtension.class)
    public void testValidateExtendedKeyUsageWithCriticalTrue() {
        extendedKeyUsage.setCritical(true);
        extendedKeyUsageValidator.validate(extendedKeyUsage, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When critical is set to false in KeyUsage
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateNullKeyUsage() {
        keyUsage.setCritical(false);
        keyUsageValidator.validate(keyUsage, true, "TestIssuer");

    }

    /**
     * Method to test validate method in negative scenario. When keyUsageTypes are empty in KeyUsage
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidateEmptyKeyUsage() {
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsage.setCritical(true);
        keyUsageValidator.validate(keyUsage, false, "TestIssuer");

    }

    /**
     * Method to test validate method in negative scenario. When ExtendedKeyUsage value is null
     */
    @Test
    public void testExtendedKeyUsageValidatorAsNull() {
        extendedKeyUsage = null;
        extendedKeyUsageValidator.validate(extendedKeyUsage, true, "TestIssuer");
        verify(logger).debug("Validating ExtendedKeyUsage in CertificateProfile{}", extendedKeyUsage);

    }

}
