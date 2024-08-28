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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;

@RunWith(MockitoJUnitRunner.class)
public class KeyUsageExtentionValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(KeyUsageExtensionValidator.class);

    @InjectMocks
    KeyUsageExtensionValidator keyUsageExtensionValidator;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    CommonProfileHelper commonProfileHelper;

    private EntityProfile entityProfile = null;
    private CertificateProfile certificateProfile = null;
    private CertificateProfileData certificateProfileData = null;
    private String certificateProfileName;
    private CertificateProfileSetUpData certificateProfileSetUpToTest;
    private EntityProfileSetUpData entityProfileSetUpToTest;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        entityProfileSetUpToTest = new EntityProfileSetUpData();
        certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        certificateProfileName = entityProfile.getCertificateProfile().getName();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();

        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions());
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions()));
        final TrustProfileData trustProfileData = new TrustProfileData();
        trustProfileData.setName("TrustProfile_1");
    }

    /**
     * Method to test positive scenario
     */
    @Test
    public void testValidateKeyUsage() {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));
        when(commonProfileHelper.getEntityProfileKeyUsageExtension(entityProfile.getKeyUsageExtension())).thenReturn(entityProfileSetUpToTest.getKeyUsageTypeList());
        when(commonProfileHelper.getCertificateProfileKeyUsageExtension(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile))).thenReturn(
                entityProfileSetUpToTest.getKeyUsageTypeList());

        keyUsageExtensionValidator.validate(entityProfile);

    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void testInvalidKeyUsageExtensionInEntityProfile() {

        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        certificateProfile.setForCAEntity(false);
        entityProfile.setCertificateProfile(certificateProfile);

        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(false);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(null);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        certificateExtensionList.add(keyUsage);
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        certificateProfile.setCertificateExtensions(certificateExtensions);

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));
        when(commonProfileHelper.getEntityProfileKeyUsageExtension(entityProfile.getKeyUsageExtension())).thenReturn(entityProfileSetUpToTest.getKeyUsageTypeList());
        when(commonProfileHelper.getCertificateProfileKeyUsageExtension(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile))).thenReturn(null);

        keyUsageExtensionValidator.validate(entityProfile);

    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void testEntityProfile_InvalidCertificateExtensions() {

        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        certificateExtensionList.add(keyUsage);
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        certificateProfile.setCertificateExtensions(certificateExtensions);

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));
        when(commonProfileHelper.getEntityProfileKeyUsageExtension(entityProfile.getKeyUsageExtension())).thenReturn(entityProfileSetUpToTest.getKeyUsageTypeList());
        when(commonProfileHelper.getCertificateProfileKeyUsageExtension(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile))).thenReturn(
                certificateProfileSetUpToTest.getKeyUsageTypeList());

        keyUsageExtensionValidator.validate(entityProfile);

    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testInvalidKeyUsage() {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        keyUsageExtensionValidator.validate(entityProfile);

    }

}
