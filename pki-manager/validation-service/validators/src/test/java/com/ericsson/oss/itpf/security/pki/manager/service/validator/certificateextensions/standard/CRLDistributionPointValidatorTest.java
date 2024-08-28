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
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidCRLDistributionPointsExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link CRLDistributionPointValidator}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLDistributionPointValidatorTest {
    @Mock
    private Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @InjectMocks
    private CRLDistributionPointValidator crlDistributionPointValidator;

    private CertificateProfile certificateProfile;
    private static CRLDistributionPoints crlDistributionPoints;
    private DistributionPoint crlDistributionPoint;
    private final static String CA_NAME_PATH = "certificateAuthorityData.name";

    private CRLDistributionPoints getCRLDistributionPoints() {
        for (final CertificateExtension certificateExtension : certificateProfile.getCertificateExtensions().getCertificateExtensions()) {
            if (certificateExtension != null) {
                if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.CRL_DISTRIBUTION_POINTS.getName())) {
                    return (CRLDistributionPoints) certificateExtension;
                }
            }
        }
        return null;
    }

    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        crlDistributionPoints = getCRLDistributionPoints();
        crlDistributionPoint = getCRLDistributionPoints().getDistributionPoints().get(0);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
        verify(logger).debug("Validating CRLDistributionPoints in Certificate Profile {}", crlDistributionPoints);
    }

    /**
     * Method to test validate method in negative scenario With Relative Issuer.
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testValidate_WithRelativeIssuer() {
        crlDistributionPoints.getDistributionPoints().get(0).setCRLIssuer("TestIssuer");
        crlDistributionPoints.getDistributionPoints().get(0).setDistributionPointName(null);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
        Mockito.verify(logger).error("If the certificate issuer is also the CRL issuer, then CRLIssuer field must be omitted and distributionPointName must be included!");
    }

    /**
     * Method to test validate method in negative scenario With Invalid Issuer.
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testValidate_WithInValidCRLIssuer() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "CAENTITY", CA_NAME_PATH)).thenReturn(getCAEntityData());
        crlDistributionPoints.getDistributionPoints().get(0).setReasonFlag(null);
        crlDistributionPoints.getDistributionPoints().get(0).setCRLIssuer("TestIssuer1");
        crlDistributionPoints.getDistributionPoints().get(0).setDistributionPointName(null);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
        Mockito.verify(logger).error("Invalid CRLIssuer name given!");
    }

    /**
     * Method to test validate method in negative scenario With Relative Issuer Not null.
     */
    @Test
    public void testValidate_WithRelativeIssuerNotNull() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "TestIssuer1", CA_NAME_PATH)).thenReturn(getCAEntityData());
        crlDistributionPoints.getDistributionPoints().get(0).setReasonFlag(null);
        crlDistributionPoints.getDistributionPoints().get(0).setCRLIssuer("TestIssuer1");
        crlDistributionPoints.getDistributionPoints().get(0).setDistributionPointName(null);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");

        Mockito.verify(persistenceManager).findEntityByName(CAEntityData.class, "TestIssuer1", CA_NAME_PATH);
    }

    /**
     * Method to test validate method in negative WithDistributionPointName.
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testValidate_WithDistributionPointName() {
        crlDistributionPoints.getDistributionPoints().get(0).setCRLIssuer(null);
        crlDistributionPoints.getDistributionPoints().get(0).setDistributionPointName(null);
        crlDistributionPoints.getDistributionPoints().get(0).setReasonFlag(null);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, null);
    }

    /**
     * Method to test CheckCRLDistributionPointParams method in negative scenario.
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testCheckCRLDistributionPointParamsWithNullData() {
        crlDistributionPoint.setDistributionPointName(null);
        crlDistributionPoint.setCRLIssuer(null);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test CheckCRLIssuerIsSameAsCertificateIssuer method in negative scenario.
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testCheckCRLIssuerIsSameAsCertificateIssuerWithRootCA() {
        crlDistributionPoint.setCRLIssuer("TestIssuer");
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test CheckCRLIssuerIsSameAsCertificateIssuer method in negative scenario with DistributionPoint as null.
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testCheckCRLIssuerIsSameAsCertificateIssuerWithNull() {
        crlDistributionPoint.setCRLIssuer("");
        crlDistributionPoint.setDistributionPointName(null);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "");
    }

    /**
     * Method to test validate method in negative scenario. When critical is set to true in CRLDistributionPoints
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testValidateCRLDistributionPointsWithCriticalTrue() {
        crlDistributionPoints.setCritical(true);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When CRLDistributionPoints is given as null
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateListOfCRLDistributionPointsWithNull() {
        crlDistributionPoints.setDistributionPoints(null);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When CRLIssuer is set to null in CRLDistributionPoints with no ReasonFlag and DistributionPointName as null
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testCheckCRLDistributionPointParamsWithCRLIssuerNull() {
        crlDistributionPoint.setCRLIssuer(null);
        crlDistributionPoint.setDistributionPointName(null);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When fullname is set to null in DistributionPointName with NameRelativeToCRLIssuer as null
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testvalidateCRLDistributionPointNameWithFullNameNull() {
        final DistributionPointName distributionPointName = new DistributionPointName();
        distributionPointName.setFullName(null);
        distributionPointName.setNameRelativeToCRLIssuer(null);
        crlDistributionPoint.setDistributionPointName(distributionPointName);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When fullname is set to invalid value in DistributionPointName
     * 
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testvalidateCRLDistributionPointNameWithFullNameInvalid() {
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> strNames = new ArrayList<String>();
        strNames.add("sdfsd");
        distributionPointName.setFullName(strNames);
        distributionPointName.setNameRelativeToCRLIssuer("TestIssuer");
        crlDistributionPoint.setDistributionPointName(distributionPointName);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When fullname is set to invalid value in DistributionPointName and throws InvalidCRLDistributionPointsExtension.
     * 
     */
    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testvalidateCRLDistributionPointNameWithFullNameInvalidValue() {
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> strNames = new ArrayList<String>();
        strNames.add("sdfsd");
        distributionPointName.setFullName(strNames);
        crlDistributionPoint.setDistributionPointName(distributionPointName);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");
    }

    @Test(expected = InvalidCRLDistributionPointsExtension.class)
    public void testvalidateCRLDistributionPointName() {
        CAEntityData caEntityData = getCAEntityData();
        caEntityData.getCertificateAuthorityData().setStatus(4);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "TestIssuer", CA_NAME_PATH)).thenReturn(caEntityData);
        final DistributionPointName distributionPointName = new DistributionPointName();
        distributionPointName.setFullName(null);
        distributionPointName.setNameRelativeToCRLIssuer("TestIssuer");
        crlDistributionPoint.setDistributionPointName(distributionPointName);
        crlDistributionPoints.getDistributionPoints().add(crlDistributionPoint);
        crlDistributionPointValidator.validate(crlDistributionPoints, true, "TestIssuer");

        Mockito.verify(logger).error("Invalid NameRelativeToCRLIssuer given!");
    }

    /**
     * Method to get CAEntityData
     * 
     * @return CAEntityData
     */
    private CAEntityData getCAEntityData() {
        final CAEntityData caEntityData = new CAEntityData();
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setStatus(1);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        return caEntityData;
    }
}
