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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.CertificateProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CommonProfileHelperTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(CommonProfileHelper.class);

    @InjectMocks
    CommonProfileHelper commonProfileHelper;

    @Mock
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Mock
    CertificateProfilePersistenceHandler certificateProfilePersistenceHandler;

    private CertificateProfile certificateProfile;
    private List<CertificateExtension> certificateExtensions;
    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateExtensions = certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile);
    }

    /**
     * This method tests getCertificateProfile method in positive scenario
     */
    @Test
    public void testGetCertificateProfile() {

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(
                certificateProfilePersistenceHandler);
        commonProfileHelper.getCertificateProfile("RootCA2_Cert_Profile");
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("RootCA2_Cert_Profile");
        Mockito.verify(certificateProfilePersistenceHandler).getProfile(certificateProfile);

    }

    /**
     * This method tests extractCertificateExtensions method in positive scenario
     */
    @Test
    public void testExtractCertificateExtensions() {
        final List<CertificateExtension> certificateExtensions = commonProfileHelper.extractCertificateExtensions(certificateProfile);
        Assert.assertNotNull(certificateExtensions);

    }

    /**
     * This method tests extractCertificateExtensions method in negative scenario
     */
    @Test(expected = CertificateExtensionException.class)
    public void testExtractCertificateExtensionsWithNull() {
        certificateProfile.setCertificateExtensions(null);
        commonProfileHelper.extractCertificateExtensions(certificateProfile);

    }

    /**
     * This method tests getEntityProfileKeyUsageExtension method in positive scenario
     */
    @Test
    public void testGetEntityProfileKeyUsageExtension() {

        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);

        final List<KeyUsageType> entityProfileKeyUsageTypes = commonProfileHelper.getEntityProfileKeyUsageExtension(keyUsage);
        Assert.assertNotNull(entityProfileKeyUsageTypes);

    }

    /**
     * This method tests getEntityProfileKeyUsageExtension method in negative scenario
     */
    @Test(expected = InvalidKeyUsageExtension.class)
    public void testGetEntityProfileKeyUsageExtensionNotCritical() {

        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(false);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);

        final List<KeyUsageType> entityProfileKeyUsageTypes = commonProfileHelper.getEntityProfileKeyUsageExtension(keyUsage);
        Assert.assertNotNull(entityProfileKeyUsageTypes);

    }

    /**
     * This method tests getEntityProfileKeyUsageExtension method in negative scenario
     */
    @Test
    public void testGetEntityProfileKeyUsageExtensionAsNull() {
        final List<KeyUsageType> entityProfileKeyUsageTypes = commonProfileHelper.getEntityProfileKeyUsageExtension(null);
        Assert.assertNull(entityProfileKeyUsageTypes);

    }

    /**
     * This method tests getCertificateProfileKeyUsageExtension method in positive scenario
     */
    @Test
    public void testGetCertificateProfileKeyUsageExtension() {
        final List<KeyUsageType> keyUsageTypes = commonProfileHelper.getCertificateProfileKeyUsageExtension(certificateExtensions);
        Assert.assertNotNull(keyUsageTypes);
    }

    /**
     * This method tests getCertificateProfileKeyUsageExtension method in negative scenario
     */
    @Test
    public void testGetCertificateProfileKeyUsageExtensionAsNull() {
        certificateExtensions.removeAll(certificateExtensions);
        final List<KeyUsageType> keyUsageTypes = commonProfileHelper.getCertificateProfileKeyUsageExtension(certificateExtensions);
        Assert.assertNull(keyUsageTypes);

    }

    /**
     * This method tests getEntityProfileExtendedKeyUsageExtension method in positive scenario
     */
    @Test
    public void testGetEntityProfileExtendedKeyUsageExtension() {

        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(false);
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ID_KP_TIME_STAMPING);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);

        final List<KeyPurposeId> keyPurposeIdsResult = commonProfileHelper.getEntityProfileExtendedKeyUsageExtension(extendedKeyUsage);
        Assert.assertNotNull(keyPurposeIdsResult);
    }

    /**
     * This method tests getEntityProfileExtendedKeyUsageExtension method in negative scenario
     */
    @Test
    public void testGetEntityProfileExtendedKeyUsageExtensionAsNull() {
        final List<KeyPurposeId> keyPurposeIds = commonProfileHelper.getEntityProfileExtendedKeyUsageExtension(null);
        Assert.assertNull(keyPurposeIds);

    }

    /**
     * This method tests getCertificateProfileExtendedKeyUsageExtension method in positive scenario
     */
    @Test
    public void testGetCertificateProfileExtendedKeyUsageExtension() {
        final List<KeyPurposeId> keyPurposeIds = commonProfileHelper.getCertificateProfileExtendedKeyUsageExtension(certificateExtensions);
        Assert.assertNotNull(keyPurposeIds);
    }

    /**
     * This method tests getCertificateProfileExtendedKeyUsageExtension method in negative scenario
     */
    @Test
    public void testGetCertificateProfileExtendedKeyUsageExtensionAsNull() {
        certificateExtensions.removeAll(certificateExtensions);
        final List<KeyPurposeId> keyPurposeIds = commonProfileHelper.getCertificateProfileExtendedKeyUsageExtension(certificateExtensions);
        Assert.assertNull(keyPurposeIds);

    }

}
