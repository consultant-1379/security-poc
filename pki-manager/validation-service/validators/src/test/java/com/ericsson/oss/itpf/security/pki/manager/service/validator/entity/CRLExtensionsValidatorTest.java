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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.IssuingDistributionPoint;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLNumberExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidIssuingDistributionPointExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidCRLDistributionPointsExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidatorFactory;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.CRLExtensionsValidator;

/**
 * Test Class for CRLExtensionsValidator.
 * 
 * @author tcskaku
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLExtensionsValidatorTest {
    @InjectMocks
    CRLExtensionsValidator cRLExtensionsValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateExtensionValidatorFactory certificateExtensionValidatorFactory;

    @Mock
    private CertificateExtensionValidator certificateExtensionValidator;

    private static final String FULL_NAME = "ldap://ldap.example.com/cn=exampleCA,dc=example,dc=com?certificateRevocationList;binary";
    private final static String CA_NAME_PATH = "certificateAuthorityData.name";

    private static final String Name = "ENM_RootCA";
    private static CertificateExtension certificateExtension;
    private CertificateProfileSetUpData certificateProfileSetUpData;

    /**
     * Method to setup initial Data.
     * 
     * @throws DatatypeConfigurationException
     */
    @Before
    public void setUpData() throws DatatypeConfigurationException {
        certificateProfileSetUpData = new CertificateProfileSetUpData();
        certificateExtension = certificateProfileSetUpData.getKeyUsage();
    }

    /**
     * Method to test validateCRLExtension.
     */
    @Test
    public void testValidateCRLExtension() {
        Mockito.when(certificateExtensionValidatorFactory.getCertificateExtensionValidator(CertificateExtensionType.SUBJECT_ALT_NAME)).thenReturn(certificateExtensionValidator);
        cRLExtensionsValidator.validateCRLExtension(CertificateExtensionType.SUBJECT_ALT_NAME, certificateExtension);

        Mockito.verify(certificateExtensionValidatorFactory).getCertificateExtensionValidator(CertificateExtensionType.SUBJECT_ALT_NAME);
    }

    /**
     * Method to test InvalidCRLNumberExtension.
     */
    @Test(expected = InvalidCRLNumberExtension.class)
    public void testValidateCRLNumberExtension_InvalidCRLNumberExtension() {
        cRLExtensionsValidator.validateCRLNumberExtension(getCRLNumber());
    }

    /**
     * Method to test validCRLNumberExtension.
     */
    @Test
    public void testValidateCRLNumberExtension() {
        cRLExtensionsValidator.validateCRLNumberExtension(new CRLNumber());
    }

    /**
     * Method to test validateIssuingDistPointExtension With FullName.
     */
    @Test
    public void testValidateIssuingDistPointExtension() {
        cRLExtensionsValidator.validateIssuingDistPointExtension(getIssuingDistributionPoint(true));
    }

    /**
     * Method to test validateIssuingDistPointExtension With Issuer.
     */
    @Test
    public void testValidateIssuingDistPointExtensionWithIssuer() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, Name, CA_NAME_PATH)).thenReturn(getCAEntityData());

        cRLExtensionsValidator.validateIssuingDistPointExtension(getIssuingDistributionPoint(false));

        Mockito.verify(persistenceManager).findEntityByName(CAEntityData.class, Name, CA_NAME_PATH);
    }

    /**
     * Method to test validateIssuingDistPointExtension With Delete Status.
     */
    @Test
    public void testValidateIssuingDistPointExtensionWithIssuer_DELETEStatus() {
        CAEntityData caEntityData = getCAEntityData();
        caEntityData.getCertificateAuthorityData().setStatus(4);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, Name, CA_NAME_PATH)).thenReturn(caEntityData);
        try {
            cRLExtensionsValidator.validateIssuingDistPointExtension(getIssuingDistributionPoint(false));
        } catch (InvalidCRLDistributionPointsExtension e) {
            Assert.assertEquals(e.getMessage(), ProfileServiceErrorCodes.INVALID_NAME_RELATIVE_TO_CRL_ISSUER);
        }
        Mockito.verify(persistenceManager).findEntityByName(CAEntityData.class, Name, CA_NAME_PATH);
    }

    /**
     * Method to test validateIssuingDistPointExtension With CRLIssuerValid.
     */
    @Test
    public void testValidateIssuingDistPointExtensionWithIssuer_CRLIssuerValid() {
        Class<Object> entityClass = null;
        Mockito.when(persistenceManager.findEntityByName(entityClass, Name, CA_NAME_PATH)).thenReturn(cRLExtensionsValidator);
        try {
            cRLExtensionsValidator.validateIssuingDistPointExtension(getIssuingDistributionPoint(false));
        } catch (InvalidCRLDistributionPointsExtension e) {
            Assert.assertEquals(e.getMessage(), ProfileServiceErrorCodes.INVALID_NAME_RELATIVE_TO_CRL_ISSUER);
        }
    }

    /**
     * Method to test validateIssuingDistPointExtension With In Valid FullName.
     */
    @Test
    public void testValidateIssuingDistPointExtension_InvalidFullName() {
        IssuingDistributionPoint issuingDistributionPoint = getIssuingDistributionPoint(true);
        issuingDistributionPoint.getDistributionPoint().getFullName().set(0, "ROOTCA");
        try {
            cRLExtensionsValidator.validateIssuingDistPointExtension(issuingDistributionPoint);
        } catch (InvalidCRLDistributionPointsExtension e) {
            Assert.assertEquals(e.getMessage(), ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_URL);
        }
    }

    /**
     * Method to test InvalidIssuingDistributionPointExtension.
     */
    @Test
    public void testValidateIssuingDistPointExtension_Exception() {
        IssuingDistributionPoint issuingDistributionPoint = getIssuingDistributionPoint(true);
        issuingDistributionPoint.setOnlyContainsAttributeCerts(true);
        issuingDistributionPoint.setOnlyContainsCACerts(true);
        try {
            cRLExtensionsValidator.validateIssuingDistPointExtension(issuingDistributionPoint);
        } catch (InvalidIssuingDistributionPointExtension e) {
            Assert.assertEquals(e.getMessage(), "In Issuing Distribution point only one which is CA certs, UserCerts or atrribute certs field is set to be true");
        }
    }

    /**
     * Method to test InvalidIssuingDistributionPointExtension.
     */
    @Test(expected = InvalidIssuingDistributionPointExtension.class)
    public void testValidateIssuingDistPointExtension_InvalidIssuingDistributionPointExtension() {
        IssuingDistributionPoint issuingDistributionPoint = getIssuingDistributionPoint(true);
        issuingDistributionPoint.setCritical(false);

        cRLExtensionsValidator.validateIssuingDistPointExtension(issuingDistributionPoint);
    }

    /**
     * Method to test INVALID_DISTRIBUTION_POINT_NAME.
     */
    @Test
    public void testValidateIssuingDistPointExtensionINVALID_DISTRIBUTION_POINT_NAME() {
        IssuingDistributionPoint issuingDistributionPoint = getIssuingDistributionPoint(true);
        List<String> fullName = new ArrayList<String>();
        issuingDistributionPoint.getDistributionPoint().setFullName(fullName);
        try {
            cRLExtensionsValidator.validateIssuingDistPointExtension(issuingDistributionPoint);
        } catch (InvalidCRLDistributionPointsExtension e) {
            Assert.assertEquals(e.getMessage(), ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_NAME);
        }
    }

    /**
     * Method to test INVALID_DISTRIBUTION_POINT_NAME.
     */
    @Test
    public void testValidateIssuingDistPointExtension_INVALID_DISTRIBUTION_POINT_NAME() {
        IssuingDistributionPoint issuingDistributionPoint = getIssuingDistributionPoint(true);
        issuingDistributionPoint.getDistributionPoint().setNameRelativeToCRLIssuer(Name);
        try {
            cRLExtensionsValidator.validateIssuingDistPointExtension(issuingDistributionPoint);
        } catch (InvalidCRLDistributionPointsExtension e) {
            Assert.assertEquals(e.getMessage(), ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_NAME);
        }
    }

    /**
     * Method to test getEntity.
     */
    @Test
    public void testGetEntity() {
        Class<Object> entityClass = null;
        Mockito.when(persistenceManager.findEntityByName(entityClass, Name, CA_NAME_PATH)).thenReturn(cRLExtensionsValidator);

        cRLExtensionsValidator.getEntity(entityClass, Name, CA_NAME_PATH);

        Mockito.verify(persistenceManager).findEntityByName(entityClass, Name, CA_NAME_PATH);
    }

    /**
     * Method to test ProfileServiceException.
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetEntity_PersistenceException() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, Name, CA_NAME_PATH)).thenThrow(new PersistenceException());

        cRLExtensionsValidator.getEntity(CAEntityData.class, Name, CA_NAME_PATH);

        Mockito.verify(persistenceManager).findEntityByName(CAEntityData.class, Name, CA_NAME_PATH);
    }

    /**
     * Method to get CRLNumber.
     * 
     * @return CRLNumber
     */
    private CRLNumber getCRLNumber() {
        final CRLNumber crlNumber = new CRLNumber();
        crlNumber.setCritical(false);
        crlNumber.setSerialNumber(123456);
        return crlNumber;
    }

    /**
     * Method to get IssuingDistributionPoint.
     * 
     * @return IssuingDistributionPoint.
     */
    private IssuingDistributionPoint getIssuingDistributionPoint(final boolean fullNameExits) {
        final IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
        issuingDistributionPoint.setCritical(true);
        DistributionPointName distributionPoint = new DistributionPointName();
        List<String> fullName = new ArrayList<String>();
        if (fullNameExits == true) {
            fullName.add(FULL_NAME);
        } else {
            distributionPoint.setNameRelativeToCRLIssuer(Name);
        }
        distributionPoint.setFullName(fullName);
        issuingDistributionPoint.setDistributionPoint(distributionPoint);
        return issuingDistributionPoint;
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
