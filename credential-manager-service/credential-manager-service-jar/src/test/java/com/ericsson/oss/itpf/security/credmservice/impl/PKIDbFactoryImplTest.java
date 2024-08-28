/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCategoriesException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiCategoryMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgrade.CredMServiceProfilesUpdateManager;
import com.ericsson.oss.itpf.security.credmservice.util.AppCategoryXmlConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.services.security.pkimock.api.MockConfigurationManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACRLManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.impl.PKICACertificateManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIConfigurationManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIEntityManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIProfileManagementServiceImpl;

@RunWith(MockitoJUnitRunner.class)
public class PKIDbFactoryImplTest {

    PKIProfileManagementServiceImpl pkiProfileManager;
    PKIEntityManagementServiceImpl pkiEntityManager;
    PKIConfigurationManagementServiceImpl pkiConfigurationManager;
    PKICACertificateManagementServiceImpl pkiCACertificateManager;

    @Mock
    CredMServiceProfilesUpdateManager credMServiceProfilesUpdateManager;

    @Mock
    SystemRecorderWrapper systemRecorder;

    @InjectMocks
    PKIDbFactory profileManager = new PKIDbFactoryImpl();

    @Before
    public void setup() {
        pkiProfileManager = new PKIProfileManagementServiceImpl();
        pkiEntityManager = new PKIEntityManagementServiceImpl();
        pkiConfigurationManager = new PKIConfigurationManagementServiceImpl();
        pkiCACertificateManager = new PKICACertificateManagementServiceImpl();
        pkiEntityManager.initEndEntityCollection();
        pkiEntityManager.initCAEntityCollection();
        pkiProfileManager.initProfileCollection();
        pkiConfigurationManager.initCategoriesCollection();
        pkiEntityManager.initCAEntityCollection();
        try {
            final Field pkiProfileManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockProfileManager");
            pkiProfileManagerField.setAccessible(true);
            pkiProfileManagerField.set(profileManager, pkiProfileManager);
            final Field pkiEntityManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockEntityManager");
            pkiEntityManagerField.setAccessible(true);
            pkiEntityManagerField.set(profileManager, pkiEntityManager);
            final Field pkiConfigurationManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockConfigurationManager");
            pkiConfigurationManagerField.setAccessible(true);
            pkiConfigurationManagerField.set(profileManager, pkiConfigurationManager);
            final Field mockProfileManagerField = PKIEntityManagementServiceImpl.class.getDeclaredField("profileManagement");
            mockProfileManagerField.setAccessible(true);
            mockProfileManagerField.set(pkiEntityManager, pkiProfileManager);
            final Field mockConfigurationManagerField = PKIEntityManagementServiceImpl.class.getDeclaredField("configurationManagement");
            mockConfigurationManagerField.setAccessible(true);
            mockConfigurationManagerField.set(pkiEntityManager, pkiConfigurationManager);
            final Field mockProfileConfigurationManagerField = PKIProfileManagementServiceImpl.class.getDeclaredField("configurationManagement");
            mockProfileConfigurationManagerField.setAccessible(true);
            mockProfileConfigurationManagerField.set(pkiProfileManager, pkiConfigurationManager);
            final Field mockCACertificateManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockCACertificateManager");
            mockCACertificateManagerField.setAccessible(true);
            mockCACertificateManagerField.set(profileManager, pkiCACertificateManager);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {

            e.printStackTrace();
        }

        ////////Collections Cleaning
        //      Entities entities = pkiEntityManager.getEntities(EntityType.CA_ENTITY, EntityType.ENTITY);
        //      if(entities.getCAEntities() != null) {
        //          for(CAEntity caTemp : entities.getCAEntities()) {
        //              pkiEntityManager.deleteEntity(caTemp);
        //          }
        //      }
        //      if(entities.getEntities() != null) {
        //          for(Entity enTemp : entities.getEntities()) {
        //              pkiEntityManager.deleteEntity(enTemp);
        //          }
        //      }
        //        Profiles profiles =pkiProfileManager.getActiveProfiles(ProfileType.TRUST_PROFILE,
        //                ProfileType.CERTIFICATE_PROFILE, ProfileType.ENTITY_PROFILE);
        //        if(profiles.getEntityProfiles() != null) {
        //            for(EntityProfile ep : profiles.getEntityProfiles()) {
        //                pkiProfileManager.deleteProfile(ep);
        //            }
        //        }
        //        if(profiles.getCertificateProfiles() != null) {
        //            for(CertificateProfile cp : profiles.getCertificateProfiles()) {
        //                pkiProfileManager.deleteProfile(cp);
        //            }
        //        }
        //        if(profiles.getTrustProfiles() != null) {
        //            for(TrustProfile tp : profiles.getTrustProfiles()) {
        //                pkiProfileManager.deleteProfile(tp);
        //            }
        //        }
        /////////////
    }

    private List<AppProfileXmlConfiguration> prepareProfiles() {

        final List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();

        AppProfileXmlConfiguration profileConfigInfo1 = null;
        AppProfileXmlConfiguration profileConfigInfo2 = null;
        AppProfileXmlConfiguration profileConfigInfo3 = null;

        final File xmlPathTest1 = new File("src/test/resources/CAtrustProfile.xml");
        final File xmlPathTest2 = new File("src/test/resources/certificateProfile.xml");
        final File xmlPathTest3 = new File("src/test/resources/endEntityProfile.xml");

        try {
            profileConfigInfo1 = new AppProfileXmlConfiguration(xmlPathTest1);
            profileConfigInfo2 = new AppProfileXmlConfiguration(xmlPathTest2);
            profileConfigInfo3 = new AppProfileXmlConfiguration(xmlPathTest3);
            appProfXConfList.add(profileConfigInfo1);
            appProfXConfList.add(profileConfigInfo2);
            appProfXConfList.add(profileConfigInfo3);
        } catch (final CredentialManagerProfilesException e) {
            e.printStackTrace();
        }

        return appProfXConfList;
    }

    //profiles with same name so it can trigger an update with different values
    private List<AppProfileXmlConfiguration> prepareProfilesRetrigger() {

        final List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();

        AppProfileXmlConfiguration profileConfigInfo1 = null;
        AppProfileXmlConfiguration profileConfigInfo2 = null;
        AppProfileXmlConfiguration profileConfigInfo3 = null;

        final File xmlPathTest1 = new File("src/test/resources/CAtrustProfile.xml");
        final File xmlPathTest2 = new File("src/test/resources/certificateProfileRetrigger.xml");
        final File xmlPathTest3 = new File("src/test/resources/endEntityProfile.xml");

        try {
            profileConfigInfo1 = new AppProfileXmlConfiguration(xmlPathTest1);
            profileConfigInfo2 = new AppProfileXmlConfiguration(xmlPathTest2);
            profileConfigInfo3 = new AppProfileXmlConfiguration(xmlPathTest3);
            appProfXConfList.add(profileConfigInfo1);
            appProfXConfList.add(profileConfigInfo2);
            appProfXConfList.add(profileConfigInfo3);
        } catch (final CredentialManagerProfilesException e) {
            e.printStackTrace();
        }

        return appProfXConfList;
    }

    private List<AppProfileXmlConfiguration> prepareProfilesWithOriginalEPPKITP() {

        final List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();

        AppProfileXmlConfiguration profileConfigInfo1 = null;
        AppProfileXmlConfiguration profileConfigInfo2 = null;
        AppProfileXmlConfiguration profileConfigInfo3 = null;

        final File xmlPathTest1 = new File("src/test/resources/CAtrustProfileWithOriginalEPPKITP.xml");
        final File xmlPathTest2 = new File("src/test/resources/certificateProfile.xml");
        final File xmlPathTest3 = new File("src/test/resources/endEntityProfile.xml");

        try {
            profileConfigInfo1 = new AppProfileXmlConfiguration(xmlPathTest1);
            profileConfigInfo2 = new AppProfileXmlConfiguration(xmlPathTest2);
            profileConfigInfo3 = new AppProfileXmlConfiguration(xmlPathTest3);
            appProfXConfList.add(profileConfigInfo1);
            appProfXConfList.add(profileConfigInfo2);
            appProfXConfList.add(profileConfigInfo3);
        } catch (final CredentialManagerProfilesException e) {
            e.printStackTrace();
        }

        return appProfXConfList;
    }

    private List<AppEntityXmlConfiguration> prepareEntities() {

        final List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        AppEntityXmlConfiguration entityConfigInfo1 = null;
        AppEntityXmlConfiguration entityConfigInfo2 = null;

        final File xmlPathTest1 = new File("src/test/resources/endEntities.xml");
        final File xmlPathTest2 = new File("src/test/resources/caEntities.xml");

        try {
            entityConfigInfo1 = new AppEntityXmlConfiguration(xmlPathTest1);
            entityConfigInfo2 = new AppEntityXmlConfiguration(xmlPathTest2);

            appEntXConfList.add(entityConfigInfo1);
            appEntXConfList.add(entityConfigInfo2);

        } catch (final CredentialManagerEntitiesException e) {
            e.printStackTrace();
        }

        return appEntXConfList;
    }

    private List<AppEntityXmlConfiguration> prepareWrongEntities() {

        final List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        AppEntityXmlConfiguration entityConfigInfo1 = null;

        final File xmlPathTest1 = new File("src/test/resources/wrongEntities.xml");

        try {
            entityConfigInfo1 = new AppEntityXmlConfiguration(xmlPathTest1);

            appEntXConfList.add(entityConfigInfo1);

        } catch (final CredentialManagerEntitiesException e) {
            e.printStackTrace();
        }

        return appEntXConfList;
    }

    private List<AppEntityXmlConfiguration> prepareCRLGenInfoCAEntities() {

        final List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        AppEntityXmlConfiguration entityConfigInfo1 = null;

        final File xmlPathTest1 = new File("src/test/resources/caEntityCRLGen.xml");

        try {
            entityConfigInfo1 = new AppEntityXmlConfiguration(xmlPathTest1);

            appEntXConfList.add(entityConfigInfo1);

        } catch (final CredentialManagerEntitiesException e) {
            e.printStackTrace();
        }

        return appEntXConfList;
    }

    private AppCategoryXmlConfiguration prepareCategories() {
        final File xmlCategoryTest = new File("src/test/resources/PKICategories.xml");
        AppCategoryXmlConfiguration acxc = null;
        try {
            acxc = new AppCategoryXmlConfiguration(xmlCategoryTest);
        } catch (final CredentialManagerCategoriesException e) {
            e.printStackTrace();
        }

        return acxc;
    }

    private AppCategoryXmlConfiguration prepareWrongCategories() {
        final File xmlCategoryTest = new File("src/test/resources/WrongPKICategories.xml");
        AppCategoryXmlConfiguration acxc = null;
        try {
            acxc = new AppCategoryXmlConfiguration(xmlCategoryTest);
        } catch (final CredentialManagerCategoriesException e) {
            e.printStackTrace();
        }

        return acxc;
    }

    @Test
    public void testPKIDbConf() {

        //		PKIDbFactoryImpl pKIDbFactory = new PKIDbFactoryImpl();
        List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
        List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        appProfXConfList = prepareProfiles();
        appEntXConfList = prepareEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(true);
        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }
    }

    @Test
    public void testPKIDbConfFail() {
        List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
        List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        appProfXConfList = prepareProfiles();
        appEntXConfList = prepareWrongEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue("Error, entities should have not been created because of not existent entity profile", false);
        } catch (ProfileNotFoundException | CANotFoundException | ProfileServiceException | EntityServiceException | EntityNotFoundException
                | PkiProfileMapperException | PkiEntityMapperException | CertificateExtensionException | InvalidSubjectException
                | MissingMandatoryFieldException | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException
                | InvalidCAException | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testPKIDbConfUpgradeEPPKITPAlreadyUpdated() {

        //              PKIDbFactoryImpl pKIDbFactory = new PKIDbFactoryImpl();
        List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
        List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        appProfXConfList = prepareProfiles();
        appEntXConfList = prepareEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(true);
        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }
    }

    @Test
    public void testPKIDbConfUpgradeEPPKITPToUpdate() {

        //              PKIDbFactoryImpl pKIDbFactory = new PKIDbFactoryImpl();
        List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
        List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        appProfXConfList = prepareProfilesWithOriginalEPPKITP();
        appEntXConfList = prepareEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(true);

        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }
    }

    @Test
    public void testPKIDbConfCRLGenUpdate() {

        List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
        List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        appProfXConfList = prepareProfiles();
        //CA Entity/s without CRL Generation Info
        appEntXConfList = prepareCRLGenInfoCAEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(true);

        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }
        //forcing CA parsing with same name to update CRL generation infos
        appEntXConfList = prepareEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(true);

        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }
    }

    @Test
    public void testPKIDbConfCPChangesCertGeneration() {
        List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
        List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        appProfXConfList = prepareProfiles();
        appEntXConfList = prepareEntities();

        try {

            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(true);

        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }

        appProfXConfList = prepareProfilesRetrigger();
        appEntXConfList = prepareEntities();

        try {
            profileManager.setCAGenUpgrade(true);
            profileManager.PKIDbConf(appProfXConfList, appEntXConfList);
            assertTrue(profileManager.getCAGenUpgrade());
            profileManager.setCAGenUpgrade(false);//reset to default

        } catch (PkiProfileMapperException | PkiEntityMapperException | ProfileServiceException | EntityServiceException | CANotFoundException
                | ProfileNotFoundException | CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException
                | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException | IOException
                | ExpiredCertificateException | RevokedCertificateException | InvalidEntityException | CRLGenerationException e) {
            assertTrue(e.getMessage(), false);
        }

    }

    @Test
    public void testPkiCategoryDbConf() {
        AppCategoryXmlConfiguration axcx = null;
        axcx = prepareCategories();
        System.out.println("Undefined category " + axcx.getUndefinedCategory() + ", Service category " + axcx.getServiceCategory());
        for (final String cat : axcx.getXmlCategories()) {
            System.out.println("Test category list " + cat);
        }
        try {
            profileManager.pkiCategoryDbConf(axcx);
            assertTrue(true);
        } catch (final PkiCategoryMapperException e) {
            assertTrue(e.getMessage(), false);
        }
    }

    @Test
    public void testPkiCategoryDbConfWrong() {
        AppCategoryXmlConfiguration axcx = null;
        axcx = prepareWrongCategories();
        try {
            profileManager.pkiCategoryDbConf(axcx);
            assertTrue(true);
        } catch (final PkiCategoryMapperException e) {
            assertTrue(e.getMessage(), false);
        }

    }

    @Test
    public void testImportExtCACerts() {

        try {
            this.profileManager.importExtCaCertificate();
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(true); //calling importCertificate (no ExtCACertMng available)
        }

        final MockExtCACertificateManagementService pkiExtCACertificateManager = Mockito.mock(MockExtCACertificateManagementService.class);
        final MockExtCACRLManagementService pkiExtCACRLManager = Mockito.mock(MockExtCACRLManagementService.class);
        Field pkiExtCACertificateManagerField = null;
        Field pkiExtCACRLManagerField = null;
        try {
            pkiExtCACertificateManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockExtCACertificateManager");
            pkiExtCACertificateManagerField.setAccessible(true);
            pkiExtCACertificateManagerField.set(this.profileManager, pkiExtCACertificateManager);
            pkiExtCACRLManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockExtCACRLManager");
            pkiExtCACRLManagerField.setAccessible(true);
            pkiExtCACRLManagerField.set(this.profileManager, pkiExtCACRLManager);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            assertTrue(false);
        }

        try {
            this.profileManager.importExtCaCertificate();
            assertTrue(true);
        } catch (final Exception e) {
            assertTrue(false);
        }
    }

    @Test
    public void testCVN() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException,
            CustomConfigurationAlreadyExistsException {
        this.profileManager.cvnInit();
        this.profileManager.readAndCheckCvn();
        this.profileManager.updateCvnOnPki();
    }

    @Test
    public void pkiCategoryConfExceptionsTest() throws EntityCategoryNotFoundException, PKIConfigurationServiceException {

        final MockConfigurationManagementService pkiConfigManager = Mockito.mock(MockConfigurationManagementService.class);
        Field pkiConfigManagerField = null;
        try {
            pkiConfigManagerField = PKIDbFactoryImpl.class.getDeclaredField("mockConfigurationManager");
            pkiConfigManagerField.setAccessible(true);
            pkiConfigManagerField.set(this.profileManager, pkiConfigManager);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            assertTrue(false);
        }
        final String undefinedCat = "UNDEFINEDTEST";
        final String serviceCat = "SERVICETEST";
        final String normCat = "CATEGORYTEST";
        final File catPath = new File("/tmp/tempCategories.xml");
        try {
            final PrintWriter writer = new PrintWriter(catPath.getAbsolutePath());
            writer.println("<?xml version='1.0' encoding='UTF-8'?>");
            writer.println(
                    "<EndEntityCategories xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:noNamespaceSchemaLocation='CategoriesSchema.xsd'>");
            writer.println("<undefinedCategoryName>" + undefinedCat + "</undefinedCategoryName>");
            writer.println("<serviceCategoryName>" + serviceCat + "</serviceCategoryName>");
            writer.println("<categoryNameList>" + normCat + "</categoryNameList>");
            writer.print("</EndEntityCategories>");
            writer.close();
        } catch (final FileNotFoundException e2) {
            assertTrue(false);
        }
        AppCategoryXmlConfiguration xmlCategories = null;
        try {
            xmlCategories = new AppCategoryXmlConfiguration(catPath);
        } catch (final CredentialManagerCategoriesException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiConfigManager.isCategoryNameAvailable(normCat)).thenReturn(true);
        final EntityCategory entityCategoryNorm = new EntityCategory();
        entityCategoryNorm.setName(normCat);
        Mockito.when(pkiConfigManager.createCategory(entityCategoryNorm)).thenThrow(new EntityCategoryAlreadyExistsException())
                .thenThrow(new InvalidEntityCategoryException());
        for (int i = 0; i < 2; i++) {
            try {
                this.profileManager.pkiCategoryDbConf(xmlCategories);
                assertTrue(false);
            } catch (final PkiCategoryMapperException e) {
                assertTrue(true);
            }
        }

        Mockito.when(pkiConfigManager.isCategoryNameAvailable(normCat)).thenThrow(new PKIConfigurationServiceException());
        ;
        try {
            this.profileManager.pkiCategoryDbConf(xmlCategories);
            assertTrue(false);
        } catch (final PkiCategoryMapperException e) {
            assertTrue(true);
        }

        //service category

        Mockito.when(pkiConfigManager.isCategoryNameAvailable(serviceCat)).thenReturn(true);
        final EntityCategory entityCategoryServ = new EntityCategory();
        entityCategoryServ.setName(serviceCat);
        Mockito.when(pkiConfigManager.createCategory(entityCategoryServ)).thenThrow(new EntityCategoryAlreadyExistsException())
                .thenThrow(new InvalidEntityCategoryException());
        for (int i = 0; i < 2; i++) {
            try {
                this.profileManager.pkiCategoryDbConf(xmlCategories);
                assertTrue(false);
            } catch (final PkiCategoryMapperException e) {
                assertTrue(true);
            }
        }

        Mockito.when(pkiConfigManager.isCategoryNameAvailable(serviceCat)).thenThrow(new PKIConfigurationServiceException());
        try {
            this.profileManager.pkiCategoryDbConf(xmlCategories);
            assertTrue(false);
        } catch (final PkiCategoryMapperException e) {
            assertTrue(true);
        }

        //undefined category

        Mockito.when(pkiConfigManager.isCategoryNameAvailable(undefinedCat)).thenReturn(true);
        final EntityCategory entityCategoryUnd = new EntityCategory();
        entityCategoryUnd.setName(undefinedCat);
        Mockito.when(pkiConfigManager.createCategory(entityCategoryUnd)).thenThrow(new EntityCategoryAlreadyExistsException())
                .thenThrow(new InvalidEntityCategoryException());
        for (int i = 0; i < 2; i++) {
            try {
                this.profileManager.pkiCategoryDbConf(xmlCategories);
                assertTrue(false);
            } catch (final PkiCategoryMapperException e) {
                assertTrue(true);
            }
        }

        Mockito.when(pkiConfigManager.isCategoryNameAvailable(undefinedCat)).thenThrow(new PKIConfigurationServiceException());
        try {
            this.profileManager.pkiCategoryDbConf(xmlCategories);
            assertTrue(false);
        } catch (final PkiCategoryMapperException e) {
            assertTrue(true);
        }

        //delete file
        assertTrue(catPath.delete());
    }

}
