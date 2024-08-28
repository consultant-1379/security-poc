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

import static org.mockito.Mockito.*;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
//import com.ericsson.oss.itpf.security.pki.manager.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard.BasicConstraintsValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link BasicConstraintsValidator}
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class BasicConstraintsValidatorTest {
    @Mock
    private Logger logger;

    @InjectMocks
    private BasicConstraintsValidator basicConstraintsValidator;

    @Mock
    private PersistenceManager persistenceManager;

    public final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";

    private CertificateProfile certificateProfile;
    private BasicConstraints basicConstraints;
    private CAEntityData caEntityData;
    private CertificateProfileData certificateProfileData;
    private EntityProfileData entityProfileData;

    private BasicConstraints getBasicConstraints() {
        for (final CertificateExtension certificateExtension : certificateProfile.getCertificateExtensions().getCertificateExtensions()) {
            if (certificateExtension != null) {
                if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.BASIC_CONSTRAINTS.getName())) {
                    return (BasicConstraints) certificateExtension;
                }
            }
        }
        return null;
    }

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();
        caEntityData = certificateProfileData.getIssuerData();

        basicConstraints = getBasicConstraints();

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("TestIssuer");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        entityProfileData = new EntityProfileData();
        entityProfileData.setId(111);
        entityProfileData.setName("TestEP");
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        basicConstraints.setPathLenConstraint(1);
        certificateProfile.getCertificateExtensions().getCertificateExtensions().clear();
        certificateProfile.getCertificateExtensions().getCertificateExtensions().add(basicConstraints);
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateProfile.getCertificateExtensions()));
        entityProfileData.setCertificateProfileData(certificateProfileData);

        caEntityData.setEntityProfileData(entityProfileData);
        when(persistenceManager.findEntityByName(CAEntityData.class, "TestIssuer", NAME_PATH_IN_CA)).thenReturn(caEntityData);
        basicConstraints.setPathLenConstraint(0);
        basicConstraintsValidator.validate(basicConstraints, true, "TestIssuer");
        verify(logger).debug("Validating BasicConstraints in CertificateProfile{}", basicConstraints);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testValidateBasicConstraintsWithIsCAFalse() {
        basicConstraints.setIsCA(false);
        basicConstraintsValidator.validate(basicConstraints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When critical is set to false in BasicConstraints
     */
    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testValidateBasicConstraintsCriticalFalse() {
        basicConstraints.setCritical(false);
        basicConstraintsValidator.validate(basicConstraints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testValidateBasicConstraintsForNonCA() {
        basicConstraintsValidator.validate(basicConstraints, false, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When pathlength is not set to zero in BasicConstraints for end entities
     */
    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testValidateBasicConstraintsForNonCAWithPathLengthNonZero() {
        basicConstraints.setIsCA(false);
        basicConstraints.setPathLenConstraint(1);
        basicConstraintsValidator.validate(basicConstraints, false, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When pathlength is not set to 1 less than issuer's pathelength in BasicConstraints for CA entities
     */
    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testValidatePathLengthConstraintForCAWithSamePathLength() {
        basicConstraints.setPathLenConstraint(20);
        entityProfileData.setCertificateProfileData(certificateProfileData);
        caEntityData.setEntityProfileData(entityProfileData);
        when(persistenceManager.findEntityByName(CAEntityData.class, "TestIssuer", NAME_PATH_IN_CA)).thenReturn(caEntityData);
        basicConstraintsValidator.validate(basicConstraints, true, "TestIssuer");
    }

}
