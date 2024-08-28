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
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;

@RunWith(MockitoJUnitRunner.class)
public class ExtendedKeyUsageValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(ExtendedKeyUsageValidator.class);

    @InjectMocks
    ExtendedKeyUsageValidator extendedKeyUsageValidator;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    CommonProfileHelper commonProfileHelper;

    private EntityProfile entityProfile = null;
    private CertificateProfile certificateProfile = null;
    private String certificateProfileName;
    private EntityProfileSetUpData entityProfileSetUpToTest;
    private CertificateProfileSetUpData certificateProfileSetUpToTest;

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
        CertificateProfileData certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();

        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions());
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions()));
        TrustProfileData trustProfileData = new TrustProfileData();
        trustProfileData.setName("TrustProfile_1");
    }

    @Test
    public void testCreateProfile_ValidExtendedKeyUsage() {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");
        commonProfileHelper.getCertificateProfile(certificateProfileName);

        extendedKeyUsageValidator.validate(entityProfile);

    }

    @Test(expected = InvalidExtendedKeyUsageExtension.class)
    public void testCreateProfile_InvalidExtendedKeyUsage() {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(false);
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(null);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        certificateExtensionList.add(extendedKeyUsage);
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        certificateProfile.setCertificateExtensions(certificateExtensions);

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateExtensionList);
        when(commonProfileHelper.getEntityProfileExtendedKeyUsageExtension(entityProfile.getExtendedKeyUsageExtension())).thenReturn(
                entityProfile.getExtendedKeyUsageExtension().getSupportedKeyPurposeIds());
        when(commonProfileHelper.getCertificateProfileExtendedKeyUsageExtension(certificateExtensionList)).thenReturn(keyPurposeIds);

        extendedKeyUsageValidator.validate(entityProfile);

    }

    @Test(expected = InvalidExtendedKeyUsageExtension.class)
    public void testCreateProfile_InvalidExtendedKeyUsage1() {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(false);
        extendedKeyUsage.setSupportedKeyPurposeIds(null);
        certificateExtensionList.add(extendedKeyUsage);
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        certificateProfile.setCertificateExtensions(certificateExtensions);

        final ExtendedKeyUsage extendedKeyUsage1 = new ExtendedKeyUsage();
        extendedKeyUsage1.setCritical(false);
        final List<KeyPurposeId> keyPurposeIds1 = new ArrayList<KeyPurposeId>();
        keyPurposeIds1.add(KeyPurposeId.ID_KP_TIME_STAMPING);
        keyPurposeIds1.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage1.setSupportedKeyPurposeIds(keyPurposeIds1);
        entityProfile.setExtendedKeyUsageExtension(extendedKeyUsage1);

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateExtensionList);
        when(commonProfileHelper.getEntityProfileExtendedKeyUsageExtension(entityProfile.getExtendedKeyUsageExtension())).thenReturn(keyPurposeIds1);
        when(commonProfileHelper.getCertificateProfileExtendedKeyUsageExtension(certificateExtensionList)).thenReturn(null);

        extendedKeyUsageValidator.validate(entityProfile);

    }

    @Test(expected = InvalidExtendedKeyUsageExtension.class)
    public void testEntityProfile_InvalidCertificateExtensions() {

        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(true);
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ID_KP_OCSP_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        certificateExtensionList.add(extendedKeyUsage);
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        certificateProfile.setCertificateExtensions(certificateExtensions);

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));
        when(commonProfileHelper.getEntityProfileExtendedKeyUsageExtension(entityProfile.getExtendedKeyUsageExtension())).thenReturn(entityProfileSetUpToTest.getKeyPurposeIdsList());
        when(commonProfileHelper.getCertificateProfileExtendedKeyUsageExtension(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile))).thenReturn(keyPurposeIds);

        extendedKeyUsageValidator.validate(entityProfile);

    }

}
