/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.ProfileManager;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCANotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerSNNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithmType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCALists;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.services.security.pkimock.impl.PKIConfigurationManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIEntityManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIProfileManagementServiceImpl;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagerImplTest {

    PKIProfileManagementServiceImpl pkiProfileManager;

    PKIEntityManagementServiceImpl pkiEntityManager;

    PKIConfigurationManagementServiceImpl pkiConfigurationManager;

    @Mock
    SystemRecorderWrapper systemRecorder;

    @InjectMocks
    ProfileManager profileManager = new ProfileManagerImpl();

    @Before
    public void setup() {
        pkiProfileManager = new PKIProfileManagementServiceImpl();
        pkiEntityManager = new PKIEntityManagementServiceImpl();
        pkiConfigurationManager = new PKIConfigurationManagementServiceImpl();
        pkiEntityManager.initEndEntityCollection();
        pkiEntityManager.initCAEntityCollection();
        pkiProfileManager.initProfileCollection();
        pkiConfigurationManager.initCategoriesCollection();

        try {
            final Field pkiProfileManagerField = ProfileManagerImpl.class.getDeclaredField("mockProfileManager");
            pkiProfileManagerField.setAccessible(true);
            pkiProfileManagerField.set(profileManager, pkiProfileManager);
            final Field pkiEntityManagerField = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            pkiEntityManagerField.setAccessible(true);
            pkiEntityManagerField.set(profileManager, pkiEntityManager);
            final Field mockProfileManagerField = PKIEntityManagementServiceImpl.class.getDeclaredField("profileManagement");
            mockProfileManagerField.setAccessible(true);
            mockProfileManagerField.set(pkiEntityManager, pkiProfileManager);
            final Field mockConfigurationManagerField = PKIEntityManagementServiceImpl.class.getDeclaredField("configurationManagement");
            mockConfigurationManagerField.setAccessible(true);
            mockConfigurationManagerField.set(pkiEntityManager, pkiConfigurationManager);
            final Field mockConfigurationManagerField2 = PKIProfileManagementServiceImpl.class.getDeclaredField("configurationManagement");
            mockConfigurationManagerField2.setAccessible(true);
            mockConfigurationManagerField2.set(pkiProfileManager, pkiConfigurationManager);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    public void testGetEntity() throws CredentialManagerServiceException {

        testCreateEntity();

        CredentialManagerEntity myCredentialManagerEndEntity = null;

        myCredentialManagerEndEntity = profileManager.getEntity("my");

        Assert.assertNotNull(myCredentialManagerEndEntity);
        Assert.assertEquals("entityProfile", myCredentialManagerEndEntity.getEntityProfileName());
        Assert.assertEquals("my", myCredentialManagerEndEntity.getSubject().getDnQualifier());
        Assert.assertEquals("1.1.1.1", myCredentialManagerEndEntity.getSubjectAltName().getIPAddress().get(0));

    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedGetEntityForNotPresent() throws CredentialManagerServiceException {

        this.deleteEntity("my");

        profileManager.getEntity("my");
    }

    @Test
    public void testGetEntityExceptions() throws EntityNotFoundException, EntityServiceException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException, CredentialManagerInvalidArgumentException,
            InvalidEntityException, InvalidEntityAttributeException {

        final PKIEntityManagementServiceImpl pkiEntityManager25 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager25 = null;
        try {
            entityManager25 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager25.setAccessible(true);
            entityManager25.set(this.profileManager, pkiEntityManager25);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiEntityManager25.getEntity(Matchers.any(Entity.class))).thenThrow(new IllegalArgumentException())
                .thenThrow(new EntityServiceException()).thenThrow(new InvalidEntityException())
                .thenThrow(new CredentialManagerInvalidEntityException()).thenThrow(new InvalidEntityAttributeException());
        try {
            this.profileManager.getEntity("entityExc");
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.getEntity("entityExc");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        //the last 3 mocked catch throws the same exceptions
        for (int i = 0; i < 3; i++) {
            try {
                this.profileManager.getEntity("entityExc");
                assertTrue(false);
            } catch (final CredentialManagerInvalidEntityException e) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testCreateEntity() throws CredentialManagerServiceException {

        this.deleteEntity("my");
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        keyGenerationAlgorithm.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        CredentialManagerEntity myCredentialManagerEntity = null;
        myCredentialManagerEntity = profileManager.createEntity("my", subject, subAltName, keyGenerationAlgorithm, "entityProfile");

        Assert.assertNotNull(myCredentialManagerEntity);
        Assert.assertEquals("entityProfile", myCredentialManagerEntity.getEntityProfileName());
        Assert.assertEquals("my", myCredentialManagerEntity.getSubject().getDnQualifier());

        Assert.assertEquals("1.1.1.1", myCredentialManagerEntity.getSubjectAltName().getIPAddress().get(0));
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedCreateEntityForEmptyName() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);

        profileManager.createEntity("", subject, subAltName, null, "myProfileName");

    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedCreateEntityForAlreadyExitst() throws CredentialManagerServiceException {

        testCreateEntity();

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);

        profileManager.createEntity("my", subject, subAltName, null, "myProfileName");

    }

    @Test
    public void testCreateEntityExceptions() throws InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException,
            AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException, EntityAlreadyExistsException,
            EntityServiceException, InvalidEntityAttributeException, InvalidProfileException, ProfileNotFoundException, CRLExtensionException,
            CRLGenerationException, InvalidCRLGenerationInfoException, InvalidEntityException, UnsupportedCRLVersionException,
            CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {

        final PKIEntityManagementServiceImpl pkiEntityManager3 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager3 = null;
        try {
            entityManager3 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager3.setAccessible(true);
            entityManager3.set(this.profileManager, pkiEntityManager3);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("entityExc");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);
        final CredentialManagerAlgorithm keyGenAl = new CredentialManagerAlgorithm();
        keyGenAl.setKeySize(2048);
        keyGenAl.setName("RSA");
        keyGenAl.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        Mockito.when(pkiEntityManager3.createEntity(Matchers.any(Entity.class))).thenThrow(new AlgorithmNotFoundException())
                .thenThrow(new CRLExtensionException("test")).thenThrow(new CRLGenerationException("test"))
                .thenThrow(new EntityAlreadyExistsException()).thenThrow(new EntityCategoryNotFoundException())
                .thenThrow(new InvalidCRLGenerationInfoException("test")).thenThrow(new InvalidEntityException())
                .thenThrow(new InvalidEntityAttributeException()).thenThrow(new InvalidEntityCategoryException())
                .thenThrow(new InvalidProfileException()).thenThrow(new InvalidSubjectAltNameExtension()).thenThrow(new InvalidSubjectException())
                .thenThrow(new MissingMandatoryFieldException()).thenThrow(new ProfileNotFoundException())
                .thenThrow(new UnsupportedCRLVersionException("test")).thenThrow(new IllegalArgumentException())
                .thenThrow(new EntityServiceException());

        for (int i = 0; i < 15; i++) {
            try {
                this.profileManager.createEntity("entityExc", subject, subAltName, keyGenAl, "entityProfileExc");
                assertTrue(false);
            } catch (final CredentialManagerInvalidEntityException e) {
                assertTrue(true);
            }
        }

        try {
            this.profileManager.createEntity("entityExc", subject, subAltName, keyGenAl, "entityProfileExc");
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.createEntity("entityExc", subject, subAltName, keyGenAl, "entityProfileExc");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testUpdateEntity() throws CredentialManagerServiceException {

        testCreateEntity();

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");

        CredentialManagerEntity myCredentialManagerEntity = null;
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);

        myCredentialManagerEntity = profileManager.updateEntity("my", subject, subAltName, null, "entityProfile");

        Assert.assertNotNull(myCredentialManagerEntity);
        Assert.assertEquals("entityProfile", myCredentialManagerEntity.getEntityProfileName());
        Assert.assertEquals("my", myCredentialManagerEntity.getSubject().getDnQualifier());
        Assert.assertEquals("1.1.1.1", myCredentialManagerEntity.getSubjectAltName().getIPAddress().get(0));
    }

    @Test(expected = CredentialManagerEntityNotFoundException.class)
    public void testFailedUpdateEntityForEntityNotFound() throws CredentialManagerEntityNotFoundException, CredentialManagerInternalServiceException,
            CredentialManagerInvalidEntityException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidArgumentException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);

        this.deleteEntity("my");

        profileManager.updateEntity("my", subject, subAltName, null, "myProfileName2");

    }

    @Test(expected = CredentialManagerProfileNotFoundException.class)
    public void testFailedUpdateEntityProfileNotFound() throws CredentialManagerServiceException {

        testCreateEntity();

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);

        profileManager.updateEntity("my", subject, subAltName, null, "myProfileName2");

    }

    @Test(expected = CredentialManagerInvalidEntityException.class)
    public void testFailedUpdateEntityInvalidArgument() throws CredentialManagerServiceException {

        testCreateEntity();

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);

        profileManager.updateEntity("", subject, subAltName, null, "myProfileName2");

    }

    @Test
    public void updateEntityTestException() throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException,
            EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException,
            InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException,
            InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileNotFoundException, UnsupportedCRLVersionException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidArgumentException {

        final PKIEntityManagementServiceImpl pkiEntityManager4 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager4 = null;
        try {
            entityManager4 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager4.setAccessible(true);
            entityManager4.set(this.profileManager, pkiEntityManager4);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("my");
        final CredentialManagerSubjectAltName subAltName = new CredentialManagerSubjectAltName();
        final List<String> iPAddressList = new ArrayList<>();
        iPAddressList.add("1.1.1.1");
        subAltName.setIPAddress(iPAddressList);
        final CredentialManagerAlgorithm keyGenAlg = new CredentialManagerAlgorithm();
        keyGenAlg.setKeySize(2048);
        keyGenAlg.setName("RSA");
        keyGenAlg.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        final Entity pkiEntity = new Entity();
        final EntityInfo pkiEnInfo = new EntityInfo();
        pkiEnInfo.setId(1);
        pkiEnInfo.setName("entityName");
        pkiEnInfo.setSubject(new Subject());
        final EntityProfile pkiEnProf = new EntityProfile();
        pkiEnProf.setId(1);
        pkiEnProf.setName("profile");
        pkiEntity.setEntityInfo(pkiEnInfo);
        pkiEntity.setEntityProfile(pkiEnProf);
        final Algorithm pkiGenAl = new Algorithm();
        pkiGenAl.setId(1);
        pkiGenAl.setKeySize(2048);
        pkiGenAl.setName("RSA");
        pkiGenAl.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        pkiEntity.setKeyGenerationAlgorithm(pkiGenAl);

        Mockito.when(pkiEntityManager4.getEntity(Matchers.any(Entity.class))).thenReturn(pkiEntity);
        Mockito.when(pkiEntityManager4.updateEntity(Matchers.any(Entity.class))).thenThrow(new AlgorithmNotFoundException())
                .thenThrow(new CRLExtensionException("test")).thenThrow(new CRLGenerationException("test"))
                .thenThrow(new EntityAlreadyExistsException()).thenThrow(new EntityCategoryNotFoundException())
                .thenThrow(new EntityNotFoundException()).thenThrow(new EntityServiceException())
                .thenThrow(new InvalidCRLGenerationInfoException("test")).thenThrow(new InvalidEntityException())
                .thenThrow(new InvalidEntityAttributeException()).thenThrow(new InvalidEntityCategoryException())
                .thenThrow(new InvalidProfileException()).thenThrow(new InvalidSubjectAltNameExtension()).thenThrow(new InvalidSubjectException())
                .thenThrow(new MissingMandatoryFieldException()).thenThrow(new ProfileNotFoundException())
                .thenThrow(new UnsupportedCRLVersionException("test"));

        try {
            this.profileManager.updateEntity("entityName", subject, subAltName, keyGenAlg, "entityProfile");
            assertTrue(false);
        } catch (final CredentialManagerInvalidEntityException e) {
            assertTrue(true);
        }
        for (int j = 0; j < 17; j++) {
            try {
                this.profileManager.updateEntity("entityName", subject, subAltName, keyGenAlg, "entityProfile");
                assertTrue(false);
            } catch (final CredentialManagerInternalServiceException | CredentialManagerEntityNotFoundException
                    | CredentialManagerInvalidEntityException | CredentialManagerProfileNotFoundException e) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testGetProfile() throws CredentialManagerServiceException {
        createProfilesOnPKI(true);

        CredentialManagerProfileInfo myCredentialManagerProfileInfo = null;

        myCredentialManagerProfileInfo = profileManager.getProfile("myEntityProfile");

        deleteProfilesOnPKI(true);

        assertNotNull(myCredentialManagerProfileInfo);
        assertEquals("CN=DEFAULT", myCredentialManagerProfileInfo.getIssuerName());
        Assert.assertEquals("subjectProfile", myCredentialManagerProfileInfo.getSubjectByProfile().getDnQualifier());
        assertEquals("sigAlg", myCredentialManagerProfileInfo.getSignatureAlgorithm().getName());
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testGetProfileFailedNotExits() throws CredentialManagerServiceException {

        profileManager.getProfile("myEntityProfile");

    }

    @Test
    public void testGetProfileExceptions()
            throws InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerInvalidArgumentException {

        final PKIProfileManagementServiceImpl pkiProfileManager2 = Mockito.mock(PKIProfileManagementServiceImpl.class);

        Field pkiProfileManagerField = null;
        try {
            pkiProfileManagerField = ProfileManagerImpl.class.getDeclaredField("mockProfileManager");
            pkiProfileManagerField.setAccessible(true);
            pkiProfileManagerField.set(this.profileManager, pkiProfileManager2);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        //exceptions on the private method
        Mockito.when(pkiProfileManager2.getProfile(Matchers.any(AbstractProfile.class))).thenThrow(new IllegalArgumentException())
                .thenThrow(new ProfileServiceException()).thenThrow(new InvalidProfileAttributeException())
                .thenThrow(new MissingMandatoryFieldException()).thenThrow(new InvalidProfileException());
        try {
            this.profileManager.getProfile("profileName");
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.getProfile("profileName");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        for (int i = 0; i < 3; i++) {
            try {
                this.profileManager.getProfile("profileName");
                assertTrue(false);
            } catch (final CredentialManagerInvalidProfileException e) {
                assertTrue(true);
            }
        }

    }

    @Test
    public void testGetTrustCAList() throws CredentialManagerServiceException {
        createProfilesOnPKI(true);

        final CredentialManagerCALists trustLists = profileManager.getTrustCAList("myEntityProfile");

        deleteProfilesOnPKI(true);

        assertNotNull(trustLists.getInternalCAList());
        System.out.println(trustLists.getInternalCAList().get(0));
        assertTrue(trustLists.getInternalCAList().get(0).equals(new CredentialManagerTrustCA("ENMManagementCA", false)));

        //        assertNotNull(trustLists.getExternalCAList());
        //        assertEquals("EricssonCA", trustLists.getExternalCAList().get(0));
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testGetTrustCAListFailedEndEntityProfileNotExitst() throws CredentialManagerServiceException {
        profileManager.getTrustCAList("myEntityProfile");
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testGetTrustCAListFailedTrustProfileNotExitst() throws CredentialManagerServiceException {
        createProfilesOnPKI(false);
        profileManager.getTrustCAList("myEntityProfile");
        deleteProfilesOnPKI(false);
    }

    @Test
    public void testIsEntityPresent() throws CredentialManagerServiceException {

        testCreateEntity();

        final boolean isPresent = profileManager.isEntityPresent("my");

        assertTrue(isPresent);
    }

    @Test
    public void testIsNotEntityPresent() throws CredentialManagerServiceException {

        final boolean isPresent = profileManager.isEntityPresent("Francesco");

        assertFalse(isPresent);
    }

    @Test(expected = CredentialManagerInternalServiceException.class)
    public void testIsEntityPresentException()
            throws EntityServiceException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {

        final PKIEntityManagementServiceImpl pkiEntityManager2 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager2 = null;
        try {
            entityManager2 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager2.setAccessible(true);
            entityManager2.set(this.profileManager, pkiEntityManager2);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiEntityManager2.isEntityNameAvailable("isEntityPresentExc", EntityType.ENTITY)).thenThrow(new EntityServiceException());
        boolean isEnt = false;
        isEnt = profileManager.isEntityPresent("isEntityPresentExc");
        assertTrue(!isEnt);

        Mockito.when(pkiEntityManager2.isEntityNameAvailable("InvalidEntityExc", EntityType.ENTITY)).thenThrow(new InvalidEntityException());
        isEnt = profileManager.isEntityPresent("InvalidEntityExc");
        assertTrue(!isEnt);
    }

    @Test
    public void testIsCAEntityPresent() {

        final PKIEntityManagementServiceImpl pkiEntityManager2 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field caEntityManager2 = null;
        try {
            caEntityManager2 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            caEntityManager2.setAccessible(true);
            caEntityManager2.set(this.profileManager, pkiEntityManager2);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        Mockito.when(pkiEntityManager2.isEntityNameAvailable("exceptionCAEntityName", EntityType.CA_ENTITY)).thenThrow(new EntityServiceException())
                .thenThrow(new InvalidEntityException());

        try {
            this.profileManager.getServicesByTrustCA("exceptionCAEntityName");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.getServicesByTrustCA("exceptionCAEntityName");
            assertTrue(false);
        } catch (final CredentialManagerCANotFoundException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testIsOtpValidFalse() throws CredentialManagerServiceException {

        final boolean isValid = profileManager.isOTPValid("pippo", "otp");

        assertFalse(isValid);
    }

    @Test
    public void testIsOtpValid() throws OTPExpiredException, EntityNotFoundException, EntityServiceException, CredentialManagerOtpExpiredException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException {

        final PKIEntityManagementServiceImpl pkiEntityManager5 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager5 = null;
        try {
            entityManager5 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager5.setAccessible(true);
            entityManager5.set(this.profileManager, pkiEntityManager5);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiEntityManager5.isOTPValid("entityName", "otp")).thenThrow(new OTPExpiredException()).thenThrow(new EntityNotFoundException())
                .thenThrow(new EntityServiceException());
        try {
            this.profileManager.isOTPValid("entityName", "otp");
            assertTrue(false);
        } catch (final CredentialManagerOtpExpiredException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.isOTPValid("entityName", "otp");
            assertTrue(false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.isOTPValid("entityName", "otp");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testReissueByEntityName() throws CredentialManagerServiceException {

        testCreateEntity();
        profileManager.reissue("my");
        final CredentialManagerEntity entity = profileManager.getEntity("my");
        assertEquals(CredentialManagerEntityStatus.REISSUE, entity.getEntityStatus());

    }

    @Test(expected = CredentialManagerEntityNotFoundException.class)
    public void testReissueByEntityNameFailedEntityNotFound()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        profileManager.reissue("Martina");
    }

    @Test(expected = CredentialManagerInvalidEntityException.class)
    public void testReissueByEntityNameFailedInvalidEntity()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        profileManager.reissue("");
    }

    @Test(expected = CredentialManagerInvalidEntityException.class)
    public void testReissueByCertificateIdInvalidEntity() throws CredentialManagerCANotFoundException, CredentialManagerSNNotFoundException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        profileManager.reissue("pippoCA", "12345");
    }

    @Test
    public void testReissueExceptions()
            throws EntityNotFoundException, EntityServiceException, InvalidSubjectAltNameExtension, InvalidSubjectException,
            MissingMandatoryFieldException, AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException,
            EntityAlreadyExistsException, InvalidEntityAttributeException, InvalidProfileException, ProfileNotFoundException, CRLExtensionException,
            CRLGenerationException, InvalidCRLGenerationInfoException, InvalidEntityException, UnsupportedCRLVersionException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {

        final PKIEntityManagementServiceImpl pkiEntityManager7 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager7 = null;
        try {
            entityManager7 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager7.setAccessible(true);
            entityManager7.set(this.profileManager, pkiEntityManager7);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        final Entity pkiEntity = new Entity();
        pkiEntity.setEntityInfo(new EntityInfo());
        pkiEntity.getEntityInfo().setStatus(EntityStatus.REISSUE);
        Mockito.when(pkiEntityManager7.getEntity(Matchers.any(Entity.class))).thenReturn(pkiEntity);
        Mockito.when(pkiEntityManager7.updateEntity(pkiEntity)).thenThrow(new AlgorithmNotFoundException())
                .thenThrow(new CRLExtensionException("test")).thenThrow(new CRLGenerationException("test"))
                .thenThrow(new EntityAlreadyExistsException()).thenThrow(new EntityCategoryNotFoundException())

                .thenThrow(new InvalidCRLGenerationInfoException("test")).thenThrow(new InvalidEntityException())
                .thenThrow(new InvalidEntityAttributeException()).thenThrow(new InvalidEntityCategoryException())
                .thenThrow(new InvalidProfileException()).thenThrow(new InvalidSubjectAltNameExtension()).thenThrow(new InvalidSubjectException())
                .thenThrow(new MissingMandatoryFieldException()).thenThrow(new ProfileNotFoundException())
                .thenThrow(new UnsupportedCRLVersionException("test")).thenThrow(new EntityServiceException())
                .thenThrow(new EntityNotFoundException());
        for (int k = 0; k < 15; k++) {
            try {
                this.profileManager.reissue("entityName");
                assertTrue(false);
            } catch (final CredentialManagerInvalidEntityException e) {
                assertTrue(true);
            }
        }
        try {
            this.profileManager.reissue("entityName");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.reissue("entityName");
            assertTrue(false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        }

    }

    @Test
    public void testReissueWithCAName()
            throws SerialNumberNotFoundException, CANotFoundException, CredentialManagerCANotFoundException, CredentialManagerSNNotFoundException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {

        try {
            this.profileManager.reissue("pippoCA", "123abc"); //at this time the mock-sec will return always null
            assertTrue(false);
        } catch (final CredentialManagerInvalidEntityException e) {
            assertTrue(true);
        }

        final PKIEntityManagementServiceImpl pkiEntityManager8 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager8 = null;
        try {
            entityManager8 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager8.setAccessible(true);
            entityManager8.set(this.profileManager, pkiEntityManager8);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiEntityManager8.getEntityNameByIssuerNameAndSerialNumber("pippoCA", "123def")).thenThrow(new CANotFoundException())
                .thenThrow(new SerialNumberNotFoundException()).thenThrow(new InvalidEntityException());
        try {
            this.profileManager.reissue("pippoCA", "123def");
            assertTrue(false);
        } catch (final CredentialManagerCANotFoundException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.reissue("pippoCA", "123def");
            assertTrue(false);
        } catch (final CredentialManagerSNNotFoundException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.reissue("pippoCA", "123def");
            assertTrue(false);
        } catch (final CredentialManagerInvalidEntityException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetServices()
            throws EntityCategoryNotFoundException, InvalidEntityCategoryException, EntityServiceException, CredentialManagerServiceException {

        testCreateEntity();
        final Set<CredentialManagerEntity> entities = profileManager.getServices();

        assertEquals(1, entities.size());

        final PKIEntityManagementServiceImpl pkiEntityManager85 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager85 = null;
        try {
            entityManager85 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager85.setAccessible(true);
            entityManager85.set(this.profileManager, pkiEntityManager85);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        Mockito.when(pkiEntityManager85.getEntitiesByCategoryv1(Matchers.any(EntityCategory.class))).thenThrow(new EntityCategoryNotFoundException())
        .thenThrow(new EntityServiceException());
        for (int k = 0; k < 2; k++) {
            try {
                this.profileManager.getServices();
                assertTrue(false);
            } catch (final CredentialManagerInternalServiceException e) {
                assertTrue(true);
            }
        }

    }

    @Test
    public void testGetServicesWithCerts()
            throws EntityCategoryNotFoundException, InvalidEntityCategoryException, EntityServiceException, CredentialManagerServiceException {

        testCreateEntity();
        final Set<CredentialManagerEntityCertificates> entities = profileManager.getServicesWithCertificates();

        assertEquals(1, entities.size());

        final PKIEntityManagementServiceImpl pkiEntityManager9 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager9 = null;
        try {
            entityManager9 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager9.setAccessible(true);
            entityManager9.set(this.profileManager, pkiEntityManager9);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        Mockito.when(pkiEntityManager9.getEntitiesByCategoryv1(Matchers.any(EntityCategory.class))).thenThrow(new EntityCategoryNotFoundException())
        .thenThrow(new EntityServiceException());
        for (int k = 0; k < 2; k++) {
            try {
                this.profileManager.getServicesWithCertificates();
                assertTrue(false);
            } catch (final CredentialManagerInternalServiceException e) {
                assertTrue(true);
            }
        }

    }

    @Test
    public void testGetServicesByTrustCAName() throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException,
            CredentialManagerInternalServiceException, EntityServiceException, ProfileServiceException {
        deleteEntitiesOnPKI(true, true);

        createCAEntity("ENMManagementCA");
        createProfilesOnPKI(true);
        createEntity("entity1");

        final Set<CredentialManagerEntity> entities = profileManager.getServicesByTrustCA("ENMManagementCA");

        assertEquals(1, entities.size());

        deleteEntity("entity1");
        deleteProfilesOnPKI(true);
        deleteCAEntity("ENMManagementCA");

        final PKIProfileManagementServiceImpl pkiProfileManager01 = Mockito.mock(PKIProfileManagementServiceImpl.class);
        final PKIEntityManagementServiceImpl pkiEntityManager01 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field pkiProfileManagerField01 = null;
        Field entityManager01 = null;

        try {
            pkiProfileManagerField01 = ProfileManagerImpl.class.getDeclaredField("mockProfileManager");
            pkiProfileManagerField01.setAccessible(true);
            pkiProfileManagerField01.set(this.profileManager, pkiProfileManager01);
            entityManager01 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager01.setAccessible(true);
            entityManager01.set(this.profileManager, pkiEntityManager01);
        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        Mockito.when(pkiEntityManager01.isEntityNameAvailable("pippoCA", EntityType.CA_ENTITY)).thenReturn(false);
        Mockito.when(pkiProfileManager01.getActiveProfiles(ProfileType.ENTITY_PROFILE)).thenThrow(new ProfileServiceException())
                .thenThrow(new InvalidProfileException()).thenThrow(new InvalidProfileAttributeException());

        try {
            this.profileManager.getServicesByTrustCA("pippoCA");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        for (int j = 0; j < 2; j++) {
            try {
                this.profileManager.getServicesByTrustCA("pippoCA");
                assertTrue(false);
            } catch (final CredentialManagerInternalServiceException e) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testGetServicesWithCertsByTrustCAName() throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException,
            CredentialManagerInternalServiceException, EntityServiceException, ProfileServiceException {
        deleteEntitiesOnPKI(true, true);

        createCAEntity("ENMManagementCA");
        createProfilesOnPKI(true);
        createEntity("entity1");

        final Set<CredentialManagerEntityCertificates> entities = profileManager.getServicesWithCertificatesByTrustCA("ENMManagementCA");

        assertEquals(1, entities.size());

        deleteEntity("entity1");
        deleteProfilesOnPKI(true);
        deleteCAEntity("ENMManagementCA");

        final PKIProfileManagementServiceImpl pkiProfileManager02 = Mockito.mock(PKIProfileManagementServiceImpl.class);
        final PKIEntityManagementServiceImpl pkiEntityManager02 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field pkiProfileManagerField02 = null;
        Field entityManager02 = null;

        try {
            pkiProfileManagerField02 = ProfileManagerImpl.class.getDeclaredField("mockProfileManager");
            pkiProfileManagerField02.setAccessible(true);
            pkiProfileManagerField02.set(this.profileManager, pkiProfileManager02);
            entityManager02 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager02.setAccessible(true);
            entityManager02.set(this.profileManager, pkiEntityManager02);
        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        Mockito.when(pkiEntityManager02.isEntityNameAvailable("pippoCA", EntityType.CA_ENTITY)).thenReturn(false);
        Mockito.when(pkiProfileManager02.getActiveProfiles(ProfileType.ENTITY_PROFILE)).thenThrow(new ProfileServiceException());
        try {
            this.profileManager.getServicesWithCertificatesByTrustCA("pippoCA");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }

    }

    @Ignore
    //Category is not managed for entityProfile
    @Test
    public void testGetServicesWithCertsByTrustCANameFails() throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException,
            CredentialManagerInternalServiceException, EntityCategoryNotFoundException, EntityCategoryInUseException,
            PKIConfigurationServiceException, EntityCategoryAlreadyExistsException, InvalidEntityCategoryException {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("SERVICE");
        pkiConfigurationManager.deleteCategory(entityCategory);
        boolean ok = false;
        try {
            profileManager.getServicesWithCertificatesByTrustCA("ENMManagementCA");
        } catch (final CredentialManagerInvalidArgumentException e) {
            ok = true;
        }
        pkiConfigurationManager.createCategory(entityCategory);
        assertTrue(ok);
    }

    @Test(expected = CredentialManagerInvalidArgumentException.class)
    public void testGetServicesWithCertsByTrustCANameEmpty()
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {

        final Set<CredentialManagerEntityCertificates> entities = profileManager.getServicesWithCertificatesByTrustCA("");

    }

    @Test(expected = CredentialManagerCANotFoundException.class)
    public void testGetServicesWithCertsByTrustCANotFound()
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {

        final Set<CredentialManagerEntityCertificates> entities = profileManager.getServicesWithCertificatesByTrustCA("ENMFakeManagementCA");

    }

    @Test
    public void testgetEntitiesByCategory() throws EntityCategoryNotFoundException, InvalidEntityCategoryException, EntityServiceException,
            CredentialManagerInternalServiceException, CredentialManagerInvalidArgumentException {

        final PKIEntityManagementServiceImpl pkiEntityManager6 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager6 = null;
        try {
            entityManager6 = ProfileManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager6.setAccessible(true);
            entityManager6.set(this.profileManager, pkiEntityManager6);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        final List<Entity> fakeEntityList = new ArrayList<Entity>();
        final Entity fakeEntity = null;
        fakeEntityList.add(fakeEntity);
        final EntityCategory cat = new EntityCategory();
        cat.setName("SERVICE");
        Mockito.when(pkiEntityManager6.getEntitiesByCategoryv1(cat)).thenThrow(new EntityCategoryNotFoundException())
        .thenThrow(new EntityServiceException()).thenThrow(new InvalidEntityCategoryException()).thenThrow(new InvalidEntityException())
        .thenThrow(new InvalidEntityAttributeException()).thenReturn(fakeEntityList);
        try {
            this.profileManager.getEntitiesByCategory(cat.getName());
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
        try {
            this.profileManager.getEntitiesByCategory(cat.getName());
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        for (int i = 0; i < 3; i++) {
            try {
                this.profileManager.getEntitiesByCategory(cat.getName());
                assertTrue(false);
            } catch (final CredentialManagerInvalidArgumentException e) {
                assertTrue(true);
            }
        }
        //exception on listEntityToSetCredentialManagerEntity
        try {
            this.profileManager.getEntitiesByCategory(cat.getName());
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
    }

    @Test
    public void getTrustCAListFromTPtest() throws CertificateExtensionException, InvalidSubjectException, MissingMandatoryFieldException,
            UnSupportedCertificateVersion, AlgorithmNotFoundException, CANotFoundException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileAttributeException, ProfileAlreadyExistsException, ProfileNotFoundException,
            ProfileServiceException, CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        TrustProfile trustProfile = new TrustProfile();

        final List<TrustCAChain> trustcachainlist = new ArrayList<TrustCAChain>();
        final TrustCAChain trustcachain2 = new TrustCAChain();
        final TrustCAChain trustcachain1 = new TrustCAChain();
        final TrustCAChain trustcachain3 = new TrustCAChain();
        final TrustCAChain trustcachainissue = new TrustCAChain();
        final CAEntity caentity1 = new CAEntity();
        final CAEntity caentity2 = new CAEntity();
        final CAEntity caentity3 = new CAEntity();
        final CAEntity caentityissuer = new CAEntity();
        final CertificateAuthority certificateauth1 = new CertificateAuthority();
        final CertificateAuthority certificateauth2 = new CertificateAuthority();
        final CertificateAuthority certificateauth3 = new CertificateAuthority();
        final CertificateAuthority certificateIssuerInfr = new CertificateAuthority();
        certificateIssuerInfr.setName("ENM_InfrastructureCA");
        certificateauth2.setName("ENM_Mail_CA");
        certificateauth1.setName("ENM_OAM_CA");
        certificateauth3.setName("ENM_SecondLevelCA");
        certificateauth1.setIssuer(certificateIssuerInfr);
        certificateauth2.setIssuer(certificateIssuerInfr);
        certificateauth3.setIssuer(certificateIssuerInfr);
        certificateIssuerInfr.setIssuer(null);
        caentity1.setCertificateAuthority(certificateauth1);
        caentity2.setCertificateAuthority(certificateauth2);
        caentity3.setCertificateAuthority(certificateauth3);
        caentityissuer.setCertificateAuthority(certificateIssuerInfr);
        trustcachain1.setInternalCA(caentity1);
        trustcachain1.setChainRequired(true);
        trustcachain2.setInternalCA(caentity2);
        trustcachain2.setChainRequired(false);
        trustcachain3.setInternalCA(caentity3);
        trustcachain3.setChainRequired(true);
        trustcachainissue.setInternalCA(caentityissuer);
        trustcachainissue.setChainRequired(true);
        trustcachainlist.add(trustcachain1);
        trustcachainlist.add(trustcachainissue);
        trustcachainlist.add(trustcachain2);
        trustcachainlist.add(trustcachain3);
        trustProfile.setTrustCAChains(trustcachainlist);
        final List<ExtCA> externalCAs = new ArrayList<ExtCA>();
        final ExtCA extCA1 = new ExtCA();
        final CertificateAuthority extCertAuth1 = new CertificateAuthority();
        extCertAuth1.setName("extCA1"); //just the name is needed for the returned list
        extCertAuth1.setId(123);
        extCA1.setCertificateAuthority(extCertAuth1);
        externalCAs.add(extCA1);
        trustProfile.setExternalCAs(externalCAs);
        trustProfile.setName("getTrustCAListFromTPtestwitchChain_TP");
        trustProfile.setType(ProfileType.TRUST_PROFILE);
        trustProfile = pkiProfileManager.createProfile(trustProfile);

        CredentialManagerCALists caLists = null;
        //Test
        caLists = profileManager.getTrustCAListFromTP(trustProfile.getName(), null);
        assertTrue(caLists.getInternalCAList().size() == 4);
        System.out.println("CALists getTrustCAListFromTP : " + caLists.getInternalCAList().toString() + " and external "
                + caLists.getExternalCAList().toString());
        this.deleteSingleProfile(trustProfile);
    }

    @Test
    public void testSetLockProfileMostlyOK() {
        this.createProfilesOnPKI(true);
        this.profileManager.setLockProfile("myCertificateProfile", CredentialManagerProfileType.CERTIFICATE_PROFILE, false);
        try {
            //ProfileNotFoundException
            this.profileManager.setLockProfile("pippoProfile", CredentialManagerProfileType.ENTITY_PROFILE, Boolean.FALSE);
            assertTrue(false);
        } catch (final CredentialManagerProfileNotFoundException e) {
            assertTrue(true);
        }
        this.deleteProfilesOnPKI(true);
    }

    @Test
    public void testSetLockProfileExceptions() {

        final PKIProfileManagementServiceImpl pkiProfileManager1 = Mockito.mock(PKIProfileManagementServiceImpl.class);

        Field profileManagerField = null;
        try {
            profileManagerField = ProfileManagerImpl.class.getDeclaredField("mockProfileManager");
            profileManagerField.setAccessible(true);
            profileManagerField.set(this.profileManager, pkiProfileManager1);
        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }
        final CertificateProfile pippoCP = new CertificateProfile();
        Mockito.when(pkiProfileManager1.getProfile(Matchers.any(AbstractProfile.class))).thenReturn(pippoCP);
        Mockito.when(pkiProfileManager1.updateProfile(pippoCP)).thenThrow(new CertificateExtensionException())
                .thenThrow(new InvalidSubjectException()).thenThrow(new MissingMandatoryFieldException())
                .thenThrow(new UnSupportedCertificateVersion()).thenThrow(new AlgorithmNotFoundException()).thenThrow(new CANotFoundException())
                .thenThrow(new EntityCategoryNotFoundException()).thenThrow(new InvalidCAException()).thenThrow(new InvalidEntityCategoryException())
                .thenThrow(new InvalidProfileException()).thenThrow(new InvalidProfileAttributeException())
                .thenThrow(new ProfileAlreadyExistsException()).thenThrow(new ProfileServiceException());
        for (int i = 0; i < 13; i++) {
            try {
                this.profileManager.setLockProfile("pippoProfile", CredentialManagerProfileType.CERTIFICATE_PROFILE, Boolean.FALSE);
            } catch (final CredentialManagerInternalServiceException e) {
                assertTrue(i == 0 || i == 1 || i == 3 || i == 12);
            } catch (final CredentialManagerInvalidArgumentException e) {
                assertTrue(i == 2);
            } catch (final CredentialManagerInvalidProfileException e) {
                assertTrue(i >= 4 && i <= 11);
            }
        }
    }

    private void createProfilesOnPKI(final boolean trustCreate) {

        try {
            CertificateProfile certificateProfile = new CertificateProfile();
            final CAEntity caentity = new CAEntity();
            final CertificateAuthority certificateauth = new CertificateAuthority();
            certificateProfile.setIssuer(caentity);
            certificateProfile.getIssuer().setCertificateAuthority(certificateauth);
            certificateProfile.getIssuer().getCertificateAuthority().setName("ericsson");
            certificateProfile.setName("myCertificateProfile");
            certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);
            final Algorithm sigAlg = new Algorithm();
            sigAlg.setKeySize(2048);
            sigAlg.setName("sigAlg");
            sigAlg.setType(AlgorithmType.SIGNATURE_ALGORITHM);
            certificateProfile.setSignatureAlgorithm(sigAlg);

            certificateProfile = pkiProfileManager.createProfile(certificateProfile);

            TrustProfile trustProfile = new TrustProfile();
            final List<String> internalCAs = new ArrayList<String>();
            internalCAs.add("ENMManagementCA");

            final List<TrustCAChain> trustcachainlist = new ArrayList<TrustCAChain>();
            final TrustCAChain trustcachain = new TrustCAChain();
            final CAEntity caentity2 = new CAEntity();
            final CertificateAuthority certificateauth2 = new CertificateAuthority();
            caentity2.setCertificateAuthority(certificateauth2);
            trustcachain.setInternalCA(caentity2);
            trustcachainlist.add(trustcachain);
            trustProfile.setTrustCAChains(trustcachainlist);
            trustProfile.getTrustCAChains().get(0).getInternalCA().getCertificateAuthority().setName("ENMManagementCA");

            //        final List<String> externalCAs = new ArrayList<String>();
            //        externalCAs.add("EricssonCA");
            //        trustProfile.setExternalCAs(externalCAs);

            trustProfile.setName("myTrustProfile");

            trustProfile.setType(ProfileType.TRUST_PROFILE);
            if (trustCreate) {
                trustProfile = pkiProfileManager.createProfile(trustProfile);
            }

            EntityProfile entityProfile = new EntityProfile();
            entityProfile.setCertificateProfile(certificateProfile);
            entityProfile.getCertificateProfile().setName(certificateProfile.getName());
            entityProfile.setName("myEntityProfile");
            entityProfile.setType(ProfileType.ENTITY_PROFILE);
            final Subject subject = new Subject();
            final Map<SubjectFieldType, String> subjectDN = new HashMap<SubjectFieldType, String>();
            subjectDN.put(SubjectFieldType.DN_QUALIFIER, "subjectProfile");

            for (final Entry<SubjectFieldType, String> entry : subjectDN.entrySet()) {
                final SubjectField subFieldTemp = new SubjectField();
                subFieldTemp.setType(entry.getKey());
                subFieldTemp.setValue(entry.getValue());
                subject.getSubjectFields().add(subFieldTemp);
            }

            entityProfile.setSubject(subject);
            final List<String> trustProfileList = new ArrayList<String>();
            trustProfileList.add(trustProfile.getName());
            entityProfile.getTrustProfiles().add(trustProfile);

            final EntityCategory entityCategory = new EntityCategory();
            entityCategory.setName("SERVICE");
            entityProfile.setCategory(entityCategory);
            entityProfile = pkiProfileManager.createProfile(entityProfile);
        } catch (CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException | UnSupportedCertificateVersion
                | AlgorithmNotFoundException | CANotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | InvalidProfileAttributeException | ProfileAlreadyExistsException | ProfileNotFoundException
                | ProfileServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void deleteProfilesOnPKI(final boolean isTrustCreate) {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("myCertificateProfile");
        try {
            pkiProfileManager.deleteProfile(certificateProfile);
        } catch (ProfileInUseException | ProfileNotFoundException | ProfileServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (isTrustCreate) {
            final TrustProfile trustProfile = new TrustProfile();
            trustProfile.setName("myTrustProfile");
            try {
                pkiProfileManager.deleteProfile(trustProfile);
            } catch (ProfileInUseException | ProfileNotFoundException | ProfileServiceException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName("myEntityProfile");
        try {
            pkiProfileManager.deleteProfile(entityProfile);
        } catch (ProfileInUseException | ProfileNotFoundException | ProfileServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void createEntity(final String entityName) {
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entity.setEntityInfo(entityInfo);
        //        Algorithm alg1 = new Algorithm();
        //        alg1.setType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM);
        //        entity.setKeyGenerationAlgorithm(alg1);
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("SERVICE");
        entity.setCategory(entityCategory);
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName("myEntityProfile");
        entity.setEntityProfile(entityProfile);
        try {
            pkiEntityManager.createEntity(entity);
        } catch (InvalidSubjectAltNameExtension | InvalidSubjectException | MissingMandatoryFieldException | AlgorithmNotFoundException
                | EntityCategoryNotFoundException | InvalidEntityCategoryException | EntityAlreadyExistsException | EntityServiceException
                | InvalidEntityAttributeException | InvalidProfileException | ProfileNotFoundException | CRLExtensionException
                | CRLGenerationException | InvalidCRLGenerationInfoException | InvalidEntityException | UnsupportedCRLVersionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void createCAEntity(final String caName) {
        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caName);
        caEntity.setCertificateAuthority(certificateAuthority);
        try {
            pkiEntityManager.createEntity(caEntity);
        } catch (InvalidSubjectAltNameExtension | InvalidSubjectException | MissingMandatoryFieldException | AlgorithmNotFoundException
                | EntityCategoryNotFoundException | InvalidEntityCategoryException | EntityAlreadyExistsException | EntityServiceException
                | InvalidEntityAttributeException | InvalidProfileException | ProfileNotFoundException | CRLExtensionException
                | CRLGenerationException | InvalidCRLGenerationInfoException | InvalidEntityException | UnsupportedCRLVersionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void deleteCAEntity(final String caName) {
        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caName);
        caEntity.setCertificateAuthority(certificateAuthority);
        try {
            pkiEntityManager.deleteEntity(caEntity);
        } catch (EntityNotFoundException | EntityInUseException | EntityServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void deleteEntity(final String entityName) {
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entity.setEntityInfo(entityInfo);
        try {
            pkiEntityManager.deleteEntity(entity);
        } catch (EntityNotFoundException | EntityInUseException | EntityServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void deleteSingleProfile(final AbstractProfile profile) {
        try {
            pkiProfileManager.deleteProfile(profile);
        } catch (ProfileInUseException | ProfileNotFoundException | ProfileServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void deleteEntitiesOnPKI(final boolean caS, final boolean enS) {
        Entities entities;
        try {
            entities = pkiEntityManager.getEntities(EntityType.CA_ENTITY, EntityType.ENTITY);

            if (caS && entities.getCAEntities() != null) {
                for (final CAEntity caTemp : entities.getCAEntities()) {
                    pkiEntityManager.deleteEntity(caTemp);
                }
            }
            if (enS && entities.getEntities() != null) {
                for (final Entity enTemp : entities.getEntities()) {
                    pkiEntityManager.deleteEntity(enTemp);
                }
            }
        } catch (final EntityServiceException | EntityNotFoundException | EntityInUseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
