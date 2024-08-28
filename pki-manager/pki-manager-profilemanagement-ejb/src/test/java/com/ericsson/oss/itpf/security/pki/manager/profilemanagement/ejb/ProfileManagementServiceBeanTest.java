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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.Serializable;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ProfileManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.ProfileManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementServiceBeanTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(ProfileManagementServiceBean.class);

    @InjectMocks
    ProfileManagementServiceBean pkiProfileManagementServiceBean;

    @Mock
    ProfileManagementAuthorizationManager profileManagementAuthorization;

    @Mock
    ProfileManager profileManager;

    @Mock
    ValidationService validationService;

    @Mock
    ValidationServiceUtils validateServiceUtils;

    @Mock
    ContextUtility contextUtility;

    @Mock
    ContextService ctxService;

    @Mock
    SystemRecorder systemRecorder;

    TrustProfileData trustProfileData = new TrustProfileData();
    TrustProfile trustProfile = new TrustProfile();
    TrustProfile trustProfile1 = new TrustProfile();

    List<TrustProfile> trustProfileList = new ArrayList<TrustProfile>();
    Profiles profiles = new Profiles();
    ValidateItem validateItem = new ValidateItem();
    final EntityCategory entityCategory = new EntityCategory();
    final CertificateProfile certificateProfile = new CertificateProfile();
    final EntityProfile entityProfile = new EntityProfile();

    private static final String CONTEXT_KEY = "User.Name";
    private static final String CREDM_CONTEXT_VALUE = "CredentialManager";

    @Before
    public void setup() {

        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();

        trustProfileData = trustProfileSetUpData.getTrustProfileData();
        trustProfileList = trustProfileSetUpData.getTrustProfileList();
        trustProfile = trustProfileList.get(0);

        profiles.setTrustProfiles(trustProfileList);

        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfiles.add(certificateProfile);
        profiles.setCertificateProfiles(certificateProfiles);

        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfiles.add(entityProfile);
        profiles.setEntityProfiles(entityProfiles);
    }

    @Test
    public void testImportProfiles() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.IMPORT);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.TRUST_PROFILE, OperationType.CREATE, trustProfile)).thenReturn(validateItemSetupData(OperationType.CREATE));
        validationService.validate(validateItemSetupData(OperationType.CREATE));
        when(profileManager.createProfile(trustProfile)).thenReturn(trustProfile);
        pkiProfileManagementServiceBean.importProfiles(profiles);
        verify(profileManager).createProfile(trustProfile);
    }

    @Test
    public void testExportTrustProfiles() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);
        when(profileManager.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        final Profiles profiles = pkiProfileManagementServiceBean.exportProfiles(ProfileType.TRUST_PROFILE);
        final TrustProfile trustProfile_dummy = profiles.getTrustProfiles().get(0);
        assertEquals(trustProfile, trustProfile_dummy);

    }

    @Test
    public void testExportAllProfiles() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);
        final Profiles trustprofiles = new Profiles();
        final Profiles entityprofiles = new Profiles();
        final Profiles certificateprofiles = new Profiles();
        trustprofiles.setTrustProfiles(profiles.getTrustProfiles());
        entityprofiles.setEntityProfiles(profiles.getEntityProfiles());
        certificateprofiles.setCertificateProfiles(profiles.getCertificateProfiles());

        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);
        profileTypes.add(ProfileType.TRUST_PROFILE);

        when(profileManager.getProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]))).thenReturn(profiles);
        final Profiles profiles_all = pkiProfileManagementServiceBean.exportProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        assertEquals(profiles.getCertificateProfiles(), profiles_all.getCertificateProfiles());
        assertEquals(profiles.getTrustProfiles(), profiles_all.getTrustProfiles());
        assertEquals(profiles.getEntityProfiles(), profiles_all.getEntityProfiles());

    }

    @Test
    public void testExportProfilesWithInvalidProfileType() {
        boolean isIllegalArgumentExceptionCaught = false;
        String errorMessage = "";
        try {
            profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);
            pkiProfileManagementServiceBean.exportProfiles();
        } catch (final IllegalArgumentException exception) {
            isIllegalArgumentExceptionCaught = true;
            errorMessage = exception.getMessage();
        }
        assertTrue(isIllegalArgumentExceptionCaught);
        assertEquals(ProfileServiceErrorCodes.NO_PROFILETYPE_PRESENT, errorMessage);
    }

    @Test
    public void testExportProfilesByTypeWithOneArgument() {
        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        final Profiles certificateProfiles = new Profiles();

        certificateProfiles.setCertificateProfiles(profiles.getCertificateProfiles());
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);
        when(profileManager.getProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]))).thenReturn(profiles);
        final Profiles profiles_certificate = pkiProfileManagementServiceBean.exportProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        assertEquals(profiles.getCertificateProfiles(), profiles_certificate.getCertificateProfiles());

    }

    @Test
    public void testExportProfilesByTypeWithTwoArguments() {

        final Profiles entityprofiles = new Profiles();
        final Profiles certificateProfiles = new Profiles();
        entityprofiles.setCertificateProfiles(profiles.getCertificateProfiles());
        certificateProfiles.setCertificateProfiles(profiles.getCertificateProfiles());
        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();
        final EntityProfile entity = new EntityProfile();
        entityProfiles.add(entity);
        certificateProfiles.setEntityProfiles(entityProfiles);

        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);

        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);
        when(profileManager.getProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]))).thenReturn(profiles);
        final Profiles profiles = pkiProfileManagementServiceBean.exportProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        assertEquals(profiles.getEntityProfiles(), certificateProfiles.getEntityProfiles());
        assertEquals(profiles.getCertificateProfiles(), certificateProfiles.getCertificateProfiles());

    }

    @Test
    public void testDeleteProfiles() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.DELETE);
        pkiProfileManagementServiceBean.deleteProfiles(profiles);
        verify(profileManager).deleteProfiles(profiles);

    }

    @Test
    public void testUpdateProfiles() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.TRUST_PROFILE, OperationType.UPDATE, trustProfile)).thenReturn(validateItemSetupData(OperationType.UPDATE));
        validationService.validate(validateItemSetupData(OperationType.UPDATE));
        pkiProfileManagementServiceBean.updateProfiles(profiles);
        verify(profileManager).updateProfiles(profiles);
    }

    @Test
    public void testCreateProfile() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.CREATE);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.TRUST_PROFILE, OperationType.CREATE, trustProfile)).thenReturn(validateItemSetupData(OperationType.CREATE));
        validationService.validate(validateItemSetupData(OperationType.CREATE));
        when(profileManager.createProfile(trustProfile)).thenReturn(trustProfile);
        final TrustProfile trustProfile_dummy = pkiProfileManagementServiceBean.createProfile(trustProfile);
        assertEquals(trustProfile, trustProfile_dummy);
    }

    @Test
    public void testUpdateProfile() {

        final HashMap<String, Serializable> map = new HashMap<String, Serializable>();
        map.put(CONTEXT_KEY, CREDM_CONTEXT_VALUE);

        Mockito.when(ctxService.getContextData()).thenReturn(map);

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);

        when(validateServiceUtils.generateProfileValidateItem(ProfileType.TRUST_PROFILE, OperationType.UPDATE, trustProfile)).thenReturn(validateItemSetupData(OperationType.UPDATE));
        validationService.validate(validateItemSetupData(OperationType.UPDATE));
        when(profileManager.updateProfile(trustProfile)).thenReturn(trustProfile);
        assertEquals(trustProfile, pkiProfileManagementServiceBean.updateProfile(trustProfile));

    }

    @Test
    public void testUpdateProfileCertificateProfile() {

        final HashMap<String, Serializable> map = new HashMap<String, Serializable>();
        map.put(CONTEXT_KEY, CREDM_CONTEXT_VALUE);

        Mockito.when(ctxService.getContextData()).thenReturn(map);

        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        when(profileManager.getModifiableStatus(certificateProfile)).thenReturn(true);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.TRUST_PROFILE, OperationType.UPDATE, trustProfile)).thenReturn(validateItemSetupData(OperationType.UPDATE));
        validationService.validate(validateItemSetupData(OperationType.UPDATE));
        when(profileManager.updateProfile(trustProfile)).thenReturn(trustProfile);
        assertEquals(trustProfile, pkiProfileManagementServiceBean.updateProfile(trustProfile));

    }

    @Test(expected = InvalidProfileException.class)
    public void testUpdateInvalidCertificateProfile() {

        final HashMap<String, Serializable> map = new HashMap<String, Serializable>();
        map.put(CONTEXT_KEY, CREDM_CONTEXT_VALUE);

        Mockito.when(ctxService.getContextData()).thenReturn(map);
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);

        when(profileManager.getModifiableStatus(certificateProfile)).thenReturn(false);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.CERTIFICATE_PROFILE, OperationType.UPDATE, certificateProfile)).thenReturn(validateItemSetupData(OperationType.UPDATE));
        validationService.validate(validateItemSetupData(OperationType.UPDATE));
        when(profileManager.updateProfile(certificateProfile)).thenReturn(certificateProfile);
        assertEquals(certificateProfile, pkiProfileManagementServiceBean.updateProfile(certificateProfile));

    }

    @Test(expected = InvalidProfileException.class)
    public void testUpdateInvalidEntityProfile() {

        final HashMap<String, Serializable> map = new HashMap<String, Serializable>();
        map.put(CONTEXT_KEY, CREDM_CONTEXT_VALUE);

        Mockito.when(ctxService.getContextData()).thenReturn(map);
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);

        when(profileManager.getModifiableStatus(entityProfile)).thenReturn(false);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.ENTITY_PROFILE, OperationType.UPDATE, entityProfile)).thenReturn(validateItemSetupData(OperationType.UPDATE));
        validationService.validate(validateItemSetupData(OperationType.UPDATE));
        when(profileManager.updateProfile(entityProfile)).thenReturn(entityProfile);
        assertEquals(entityProfile, pkiProfileManagementServiceBean.updateProfile(entityProfile));

    }

    @Test
    public void testUpdateProfileModifiableTrue() {

        final HashMap<String, Serializable> map = new HashMap<String, Serializable>();
        map.put(CONTEXT_KEY, CREDM_CONTEXT_VALUE);

        Mockito.when(ctxService.getContextData()).thenReturn(map);
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);

        when(profileManager.getModifiableStatus(entityProfile)).thenReturn(true);
        when(validateServiceUtils.generateProfileValidateItem(ProfileType.ENTITY_PROFILE, OperationType.UPDATE, entityProfile)).thenReturn(validateItemSetupData(OperationType.UPDATE));
        validationService.validate(validateItemSetupData(OperationType.UPDATE));
        when(profileManager.updateProfile(entityProfile)).thenReturn(entityProfile);
        assertEquals(entityProfile, pkiProfileManagementServiceBean.updateProfile(entityProfile));

    }

    @Test
    public void testGetProfile() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);
        when(profileManager.getProfile(trustProfile)).thenReturn(trustProfile);
        final TrustProfile trustProfile_dummy = pkiProfileManagementServiceBean.getProfile(trustProfile);
        assertEquals(trustProfile, trustProfile_dummy);
    }

    @Test
    public void testDeteleProfile() {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.DELETE);
        pkiProfileManagementServiceBean.deleteProfile(trustProfile);
        verify(profileManager).deleteProfile(trustProfile);
    }

    @Test
    public void testIsProfileNameAvailable() {

        when(profileManager.isNameAvailable("TestProfile", ProfileType.TRUST_PROFILE)).thenReturn(true);
        assertTrue(pkiProfileManagementServiceBean.isProfileNameAvailable("TestProfile", ProfileType.TRUST_PROFILE));
    }

    /**
     * 
     * @param operationType
     *            Type of operation whether create/update
     * @return ValidateItem
     */
    private ValidateItem validateItemSetupData(final OperationType operationType) {
        validateItem.setItem(trustProfile);
        validateItem.setItemType(ItemType.TRUST_PROFILE);
        validateItem.setOperationType(operationType);
        return validateItem;

    }

    @Test
    public void testGetActiveProfiles() {
        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);
        profileTypes.add(ProfileType.TRUST_PROFILE);

        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);
        when(profileManager.getActiveProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]), true)).thenReturn(profiles);
        final Profiles profile = pkiProfileManagementServiceBean.getActiveProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));
        assertEquals(profiles.getCertificateProfiles(), profile.getCertificateProfiles());
        assertEquals(profiles.getTrustProfiles(), profile.getTrustProfiles());
        assertEquals(profiles.getEntityProfiles(), profile.getEntityProfiles());
    }

    @Test
    public void testGetActiveProfilesThrowsIllegalArgumentException() {
        boolean isIllegalArgumentExceptionCaught = false;
        String errorMessage = "";
        try {
            profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);
            pkiProfileManagementServiceBean.getActiveProfiles();
        } catch (final IllegalArgumentException illegalArgumentException) {
            isIllegalArgumentExceptionCaught = true;
            errorMessage = illegalArgumentException.getMessage();
        }
        assertTrue(isIllegalArgumentExceptionCaught);
        assertEquals(ProfileServiceErrorCodes.NO_PROFILETYPE_PRESENT, errorMessage);
    }
}
