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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CAIssuerValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CAIssuerValidator.class);

    @InjectMocks
    CAIssuerValidator caIssuerValidator;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    private PersistenceManager persistenceManager;
    @Mock
    CAEntity caEntity;

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private final static String CA_NAME_PATH = "certificateAuthorityData.name";
    private CAEntityData caEntityData;

    /**
     * Method to provide dummy data for tests.
     *
     * @throws DatatypeConfigurationException
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();
        caEntityData = certificateProfileData.getIssuerData();
    }

    /**
     * Method to test validateCAIssuer in positive scenario.
     */
    public void testValidateCAIssuer() {
        final String issuerName = caEntity.getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(caEntityData);
        caIssuerValidator.validate(certificateProfile);

    }

    /**
     * This Method tests validateCAIssuer in negative scenario, with Issuer name null.
     */
    @Test
    public void testValidateCAIssuerWithNullIssuerName() {
        certificateProfile.setIssuer(null);
        caIssuerValidator.validate(certificateProfile);

    }

    /**
     * This Method tests validateCAIssuer in negative scenario, with CAName null.
     */
    @Test
    public void testValidateCAIssuerWithNullCAName() {
        final CAEntity issuerName = certificateProfile.getIssuer();
        issuerName.getCertificateAuthority().setName(null);
        caIssuerValidator.validate(certificateProfile);

    }

    /**
     * This Method tests validateCAIssuer in negative scenario, with CAEntityData null.
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateCAIssuerWithNullCAEntityData() {
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(null);
        caIssuerValidator.validate(certificateProfile);
        verify(caIssuerValidator).validate(certificateProfile);
    }

    /**
     * This Method tests validateCAIssuer in negative scenario, while fetching the CAEntity from DB.
     */
    @Test(expected = ProfileServiceException.class)
    public void testValidateCAIssuerWithDBErrors() {
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenThrow(new PersistenceException());
        caIssuerValidator.validate(certificateProfile);
    }

    /**
     * This Method tests validateCAIssuer in negative scenario, with External CA.
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateCAIssuerWithExternalCA() {
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(caEntityData);
        caEntityData.setExternalCA(true);
        caIssuerValidator.validate(certificateProfile);
        verify(caIssuerValidator).validate(certificateProfile);
    }

    /**
     * This Method tests validateCAIssuer in negative scenario, with CAStatus as Deleted.
     */
    @Test(expected = InvalidCAException.class)
    public void testValidateCAStatusAsDeleted() {
        final CAEntityData caEntity = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setStatus(CAStatus.DELETED.getId());
        caEntity.setCertificateAuthorityData(certificateAuthorityData);
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(caEntity);
        caIssuerValidator.validate(certificateProfile);
        verify(caIssuerValidator).validate(certificateProfile);
    }

}
