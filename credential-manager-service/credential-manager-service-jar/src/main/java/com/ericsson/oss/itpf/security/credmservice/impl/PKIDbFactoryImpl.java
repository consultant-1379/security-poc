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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.naming.ldap.LdapName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManager;
import com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLServiceException;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.SpecificEntitiesLists;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiCategoryMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlEntityProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlTrustProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEntity;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.SpecificProfilesLists;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgrade.CredMServiceProfilesUpdateManager;
import com.ericsson.oss.itpf.security.credmservice.util.AppCategoryXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.util.Base64Reader;
import com.ericsson.oss.itpf.security.credmservice.util.GlobalPropertiesPKIParser;
import com.ericsson.oss.itpf.security.credmservice.util.PkiCAEntityMapper;
import com.ericsson.oss.itpf.security.credmservice.util.PkiCertificateProfileMapper;
import com.ericsson.oss.itpf.security.credmservice.util.PkiEntityMapper;
import com.ericsson.oss.itpf.security.credmservice.util.PkiEntityProfileMapper;
import com.ericsson.oss.itpf.security.credmservice.util.PkiTrustProfileMapper;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;
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
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockConfigurationManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockEntityManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACRLManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockProfileManagementService;

@Stateless
public class PKIDbFactoryImpl implements PKIDbFactory {

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory#PKIDbConf (java.util.List, java.util.List)
     */

    @EServiceRef
    ProfileManagementService pkiProfileManager;

    @EServiceRef
    MockProfileManagementService mockProfileManager;

    @EServiceRef
    EntityManagementService pkiEntityManager;

    @EServiceRef
    MockEntityManagementService mockEntityManager;

    @EServiceRef
    CACertificateManagementService pkiCACertificateManager;

    @EServiceRef
    MockCACertificateManagementService mockCACertificateManager;

    @EServiceRef
    ExtCACertificateManagementService pkiExtCACertificateManager;

    @EServiceRef
    MockExtCACertificateManagementService mockExtCACertificateManager;

    @EServiceRef
    ExtCACRLManagementService pkiExtCACRLManager;

    @EServiceRef
    MockExtCACRLManagementService mockExtCACRLManager;

    @EServiceRef
    CRLManagementService pkiIntCACRLManager;

    @EServiceRef
    CRLManagementService mockIntCACRLManager;

    @Inject
    CertificateManager certificateManager;

    @EServiceRef
    PKIConfigurationManagementService pkiConfigurationManager;

    @EServiceRef
    MockConfigurationManagementService mockConfigurationManager;

    @Inject
    private ContextService ctxService;

    private static final Logger log = LoggerFactory.getLogger(PKIDbFactoryImpl.class);

    private static boolean caGenTrigger = false;

    @Inject
    private CredMServiceProfilesUpdateManager credMServiceProfilesUpdateManager;

    @Inject
    private SystemRecorderWrapper systemRecorder;

    @SuppressWarnings("unused")
    @Override
    public void PKIDbConf(final List<AppProfileXmlConfiguration> xmlProfiles, final List<AppEntityXmlConfiguration> xmlEntities)
            throws PkiProfileMapperException, PkiEntityMapperException, ProfileServiceException, EntityServiceException, CANotFoundException,
            ProfileNotFoundException, EntityNotFoundException, CertificateExtensionException, InvalidSubjectException, MissingMandatoryFieldException,
            UnSupportedCertificateVersion, AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileAttributeException, ProfileAlreadyExistsException, EntityAlreadyExistsException,
            InvalidEntityAttributeException, InvalidProfileException, UnsupportedCRLVersionException, CRLExtensionException,
            InvalidCRLGenerationInfoException, CertificateGenerationException, CertificateServiceException, IOException, ExpiredCertificateException,
            RevokedCertificateException, InvalidEntityException, CRLGenerationException {

        //		if (credMServiceProfilesUpdateManager.isInitDone() == false) {
        //			credMServiceProfilesUpdateManager.init();
        //		}

        final SpecificProfilesLists genericProfilesList = new SpecificProfilesLists();

        if (xmlProfiles != null && !xmlProfiles.isEmpty()) {
            genericProfilesList.splitIntoSpecificLists(xmlProfiles);
        }

        for (final XmlTrustProfile xmlXmlFormatTrustProfile : genericProfilesList.getTrustProfilesList()) {

            final TrustProfile xmlPkiFormatTrustProfile = PkiTrustProfileMapper.ConvertTrustProfileFrom(xmlXmlFormatTrustProfile);
            /**
             * Create a Trust Profile or Certificate Profile or Entity Profile.
             *
             * @param Object
             *            of TrustProfile/CertificateProfile/EntityProfile.
             * @return Created profile object.
             * @throws InternalServiceException
             *             thrown when any internal Database errors or service exception occur.
             * @throws CANotFoundException
             *             thrown when given CAs in trustProfile doesn't exists or in revoked state
             * @throws ProfileNotFoundException
             *             thrown when given CertificateProfile or TrustProfile inside Entity Profile doesn't exists or in inactive state.
             */

            // CVN start
            // call first for initial if not present; else call for trust db
            // update ....
            // for eppki_tp we need to include the external ca (only update ??)
            // CVN end

            if (this.getProfileManager().isProfileNameAvailable(xmlPkiFormatTrustProfile.getName(), xmlPkiFormatTrustProfile.getType())) {
                log.info("PKIDbConf : pkiTrustProfile = " + xmlPkiFormatTrustProfile.getName() + " creating ...");
                final TrustProfile pkiTrustProfileRet = this.getProfileManager().createProfile(xmlPkiFormatTrustProfile);
            } else {

                final TrustProfile pkiPkiFormatTrustProfile = this.getProfileManager().getProfile(xmlPkiFormatTrustProfile);
                //
                // UPGRADE CALL (pkiTrustProfile, pkiTrustProfileRet) // first
                // from xml, second from db .
                // if return null no action are performed
                //
                log.info("PKIDbConf : pkiTrustProfile = " + pkiPkiFormatTrustProfile.getName() + " already exists! calling CVN stuff");

                final TrustProfile trustProfileToUse = credMServiceProfilesUpdateManager.checkTrustProfileUpgradePath(xmlPkiFormatTrustProfile,
                        pkiPkiFormatTrustProfile);

                if (trustProfileToUse != null) {
                    log.info("PKIDbConf : pkiTrustProfile = " + trustProfileToUse.getName() + " Updating due to cvn stuff");
                    this.getProfileManager().updateProfile(trustProfileToUse);
                }
            }
        }

        for (final XmlCertificateProfile xmlCertificateProfile : genericProfilesList.getCertificateProfilesList()) {
            final CertificateProfile xmlpkiFormatCertificateProfile = PkiCertificateProfileMapper
                    .ConvertCertificateProfileFrom(xmlCertificateProfile);

            // CVN start
            // for certificateProfile is not present it is written
            // if present we read from db, get id , and update from wxl
            // CVN end

            if (this.getProfileManager().isProfileNameAvailable(xmlpkiFormatCertificateProfile.getName(), xmlpkiFormatCertificateProfile.getType())) {
                log.info("PKIDbConf : pkiCertificateProfile = " + xmlpkiFormatCertificateProfile.getName() + " creating ...");
                final CertificateProfile pkiCertificateProfileRet = this.getProfileManager().createProfile(xmlpkiFormatCertificateProfile);
            } else {
                log.info("PKIDbConf : pkiCertificateProfile = " + xmlpkiFormatCertificateProfile.getName() + " already exists! calling CVN stuff");
                final CertificateProfile pkiPkiFormatCertificateProfile = this.getProfileManager().getProfile(xmlpkiFormatCertificateProfile);

                //
                // pki = UPGRADE CALL (pkiCertificateProfile,
                // pkiCertificateProfileRet) // first from xml, second from db
                //

                CertificateProfile certificateProfileToUse = credMServiceProfilesUpdateManager
                        .checkCertificateProfileUpgradePath(xmlpkiFormatCertificateProfile, pkiPkiFormatCertificateProfile);

                if (certificateProfileToUse != null) {
                    log.info("PKIDbConf : certificateProfile = " + certificateProfileToUse.getName() + " Updating due to cvn stuff");
                    certificateProfileToUse = this.getProfileManager().updateProfile(certificateProfileToUse);
                }
            }
        }

        // CVN start
        // for entity profile first we look to global properties
        // these capabilities are higher priority compared with xml stuff
        // if profile not existing we creating with global properties present
        // if present no action are performed
        // CVN end

        final LdapName sedLdap = GlobalPropertiesPKIParser.getPKI_EntityProfile_DN();
        final List<SubjectField> sedSubjList = GlobalPropertiesPKIParser.fromLdapNameToSubjectFieldList(sedLdap);
        if (sedLdap.size() > sedSubjList.size()) {
            log.info("PKIDbConf : " + (sedLdap.size() - sedSubjList.size())
                    + " PKI DB global.properties entries have been filtered in final EP subject values list");
            systemRecorder.recordEvent(
                    "Filtered " + (sedLdap.size() - sedSubjList.size())
                            + " custom SED entries for Entity Profiles DN, only O/OU/C will be taken over",
                    EventLevel.COARSE, "Credential Manager Service", "PKIDbFactoryImpl", "");
        }
        for (final XmlEntityProfile xmlEntityProfile : genericProfilesList.getEntityProfilesList()) {
            final EntityProfile xmlpkiFormatEntityProfile = PkiEntityProfileMapper.ConvertEntityProfileFrom(xmlEntityProfile);

            if (this.getProfileManager().isProfileNameAvailable(xmlpkiFormatEntityProfile.getName(), xmlpkiFormatEntityProfile.getType())) {
                log.info("PKIDbConf : pkiEntityProfile = " + xmlpkiFormatEntityProfile.getName() + " creating ...");
                if (xmlpkiFormatEntityProfile.getSubject() == null) {
                    xmlpkiFormatEntityProfile.setSubject(new Subject());
                }

                final List<SubjectField> effectiveSedSubjList = GlobalPropertiesPKIParser.skimSubject(this.getProfileManager()
                        .getProfile(xmlpkiFormatEntityProfile.getCertificateProfile()).getSubjectCapabilities().getSubjectFields(), sedSubjList);
                xmlpkiFormatEntityProfile.getSubject().setSubjectFields(
                        GlobalPropertiesPKIParser.mergeSEDAndEP(effectiveSedSubjList, xmlpkiFormatEntityProfile.getSubject().getSubjectFields()));

                final EntityProfile entityProfileToUse = this.getProfileManager().createProfile(xmlpkiFormatEntityProfile);
            } else {
                //
                // pkiEntityProfileRet =
                // this.getProfileManager().getProfile(pkiEntityProfile)
                // UPGRADE CALL (pkiEntityProfile, pkiEntityProfileRet) // first
                // from xml, second from db
                //
                log.info("PKIDbConf : pkiEntityProfile = " + xmlpkiFormatEntityProfile.getName() + " already exists ! calling CVN stuff");
                final EntityProfile pkipkiFormatEntityProfile = this.getProfileManager().getProfile(xmlpkiFormatEntityProfile);

                final EntityProfile entityProfileToUse = credMServiceProfilesUpdateManager.checkEntityProfileUpgradePath(xmlpkiFormatEntityProfile,
                        pkipkiFormatEntityProfile);

                if (entityProfileToUse != null) {
                    log.info("PKIDbConf : pkiEntityProfile = " + entityProfileToUse.getName() + " Updating due to cvn stuff");

                    this.getProfileManager().updateProfile(entityProfileToUse);
                }
            }
        }

        final SpecificEntitiesLists genericEntitiesList = new SpecificEntitiesLists();

        if (xmlEntities != null && !xmlEntities.isEmpty()) {
            genericEntitiesList.splitIntoSpecificLists(xmlEntities);
        }

        // CVN start
        // for CA entity is not exist it is created
        // if exists
        // CVN end

        for (final XmlCAEntity xmlCAEntityItem : genericEntitiesList.getCAentitiesList()) {

            final CAEntity xmlpkiFormatCAEntity = PkiCAEntityMapper.ConvertEntityFrom(xmlCAEntityItem);

            if (this.getEntityManager().isEntityNameAvailable(xmlpkiFormatCAEntity.getCertificateAuthority().getName(),
                    xmlpkiFormatCAEntity.getType())) {

                log.info("PKIDbConf : pkiCAEntity = " + xmlpkiFormatCAEntity.getCertificateAuthority().getName() + " creating ...");

                final EntityProfile profileCA = this.getProfileManager().getProfile(xmlpkiFormatCAEntity.getEntityProfile());
                if (profileCA.getSubject() != null) {
                    final List<SubjectField> addedSubjectList = new ArrayList<SubjectField>();
                    log.info("PKIDbConf : pkiCAEntity = " + xmlpkiFormatCAEntity.getCertificateAuthority().getName()
                            + " updating entity subject with entity profile info " + profileCA.getName() + " ...");
                    for (final SubjectField profileSubField : profileCA.getSubject().getSubjectFields()) {
                        boolean found = false;
                        for (final SubjectField caSubField : xmlpkiFormatCAEntity.getCertificateAuthority().getSubject().getSubjectFields()) {
                            if (profileSubField.getType().equals(caSubField.getType())) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            SubjectField addedSubjectField = new SubjectField();
                            addedSubjectField = profileSubField;
                            addedSubjectList.add(addedSubjectField);
                        }
                    }
                    xmlpkiFormatCAEntity.getCertificateAuthority().getSubject().getSubjectFields().addAll(addedSubjectList);
                }

                final CAEntity pkiCAEntityRet = this.getEntityManager().createEntity(xmlpkiFormatCAEntity);
                this.getCertificateManager().generateCertificate(pkiCAEntityRet.getCertificateAuthority().getName());
            } else {

                log.info("PKIDbConf : pkiCAEntity = " + xmlpkiFormatCAEntity.getCertificateAuthority().getName()
                        + " already exists ! calling CVN stuff");

                final CAEntity pkiPkiFormatCaEntity = this.getEntityManager().getEntity(xmlpkiFormatCAEntity);

                final CAEntity cAEntityToUse = credMServiceProfilesUpdateManager.checkCAEntityUpgradePath(xmlpkiFormatCAEntity, pkiPkiFormatCaEntity);

                // UPGRADE CALL (pkiCAEntity, pkiCaEntityToUpdate) // first from
                // xml, second from db

                // to be understand if needed ...

                if (cAEntityToUse != null) {
                    log.info("PKIDbConf : pkiCAEntity = " + cAEntityToUse.getCertificateAuthority().getName() + " Updating due to cvn stuff");
                    this.getEntityManager().updateEntity(cAEntityToUse);
                }

                if (this.getCAGenUpgrade()) {

                    log.info("PKIDbConf : pkiCAEntity = " + xmlpkiFormatCAEntity.getCertificateAuthority().getName()
                            + " ... Generating new certificate ...");
                    this.getCertificateManager().generateCertificate(xmlpkiFormatCAEntity.getCertificateAuthority().getName());
                }

            }
        }

        for (final XmlEntity xmlEntityItem : genericEntitiesList.getEntitiesList()) {

            /**
             * Create a CAEntity/Entity.
             *
             * @param entity
             *            Object of CAEntity/Entity.
             * @return return created entity object.
             * @throws InternalServiceException
             *             thrown when any internal Database errors or service exception occur.
             * @throws ProfileNotFoundException
             *             throw if given entity contains the entity profile that doesn't exists.
             *
             */

            final Entity pkiEntity = PkiEntityMapper.ConvertEntityFrom(xmlEntityItem);

            if (this.getEntityManager().isEntityNameAvailable(pkiEntity.getEntityInfo().getName(), pkiEntity.getType())) {
                log.info("PKIDbConf : pkiEntity = " + pkiEntity.getEntityInfo().getName() + " creating ...");
                final Entity pkiEntityRet = this.getEntityManager().createEntity(pkiEntity);
            } else {
                log.info("PKIDbConf : pkiEntity = " + pkiEntity.getEntityInfo().getName() + " already exists !");
            }

        }

    }

    @Override
    public void setCAGenUpgrade(final boolean trigger) {
        PKIDbFactoryImpl.caGenTrigger = trigger;
    }

    @Override
    public boolean getCAGenUpgrade() {
        return PKIDbFactoryImpl.caGenTrigger;
    }

    public ProfileManagementService getProfileManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            return this.mockProfileManager;
        } else {
            return this.pkiProfileManager;
        }
    }

    public EntityManagementService getEntityManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            return this.mockEntityManager;
        } else {
            return this.pkiEntityManager;
        }
    }

    public CACertificateManagementService getCertificateManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            return this.mockCACertificateManager;
        } else {
            return this.pkiCACertificateManager;
        }
    }

    public ExtCACertificateManagementService getExtCertificateManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            return this.mockExtCACertificateManager;
        } else {
            return this.pkiExtCACertificateManager;
        }
    }

    public ExtCACRLManagementService getExtCACRLManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockExtCACrlManager()) {
            return this.mockExtCACRLManager;
        } else {
            return this.pkiExtCACRLManager;
        }
    }

    public CRLManagementService getIntCACRLManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockIntCACrlManager()) {
            return this.mockIntCACRLManager;
        } else {
            return this.pkiIntCACRLManager;
        }
    }

    public PKIConfigurationManagementService getPkiConfigurationManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            return this.mockConfigurationManager;
        } else {
            return this.pkiConfigurationManager;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory# importExtCaCertificate()
     */
    @Override
    public void importExtCaCertificate() throws Exception {
        final String[] caNames = PKIExtCAManagementSolution.getExtCAName();
        for (final String caName : caNames) {
            try {
                if (this.getEntityManager().isEntityNameAvailable(caName, EntityType.CA_ENTITY)) {
                    log.info("Starting to import external CA: " + caName);
                    final String extCAPath = PKIExtCAManagementSolution.getExtCAPath();
                    File storeFilePath = null;

                    if (extCAPath != null) {
                        final String fileName = extCAPath + "/" + caName + ".pem";
                        storeFilePath = new File(fileName);
                    } else {
                        storeFilePath = new File(CertificateManagerImpl.class.getClassLoader().getResource(caName + ".pem").getPath());
                    }
                    if (storeFilePath != null && storeFilePath.exists()) {
                        final Base64Reader br = new Base64Reader("", storeFilePath.getPath(), "", "", "");

                        final Certificate pemCertificate = br.getCertificate("");
                        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        final InputStream inputStream = new ByteArrayInputStream(pemCertificate.getEncoded());
                        final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
                        this.getExtCertificateManager().importCertificate(caName, certificate, false);
                        final List<X509CRL> crlList = this.getCRLsFromFile(caName);
                        for (final X509CRL x509CRL : crlList) {
                            final ExternalCRLInfo crl = new ExternalCRLInfo();
                            final X509CRLHolder x509CRLHolder = new X509CRLHolder(x509CRL);
                            crl.setX509CRL(x509CRLHolder);
                            crl.setAutoUpdate(false);
                            crl.setNextUpdate(x509CRL.getNextUpdate());
                            this.getExtCACRLManager().addExternalCRLInfo(caName, crl);
                        }
                    }
                }
            } catch (final Exception e) {
                log.error("Exception during ext CA import" + e.toString());
                throw e;
            }
        }

    }

    private List<X509CRL> getCRLsFromFile(final String caName) throws CredentialManagerCRLServiceException {

        final List<X509CRL> caCrls = new ArrayList<>();

        final String[] extSubCANames = PKIExtCAManagementSolution.getExtSubCAName(caName);
        if (extSubCANames != null) {
            final String extCAPath = PKIExtCAManagementSolution.getExtCAPath();
            for (final String subCAName : extSubCANames) {
                X509CRL crl;
                try {
                    crl = readCRL(extCAPath, subCAName);
                    if (crl != null) {
                        caCrls.add(crl);
                    }
                } catch (final IOException e) {
                    log.warn("error managing CRL for CA {}", subCAName);
                    log.warn("IOException on file", e);
                }
            }
        }
        return caCrls;
    }

    /**
     * @param caCrls
     * @param extCAPath
     * @param subCAName
     * @throws IOException
     */
    private X509CRL readCRL(final String extCAPath, final String subCAName) throws IOException {
        InputStream crlFile = null;
        try {
            try {
                if (extCAPath != null) {
                    final String fileName = extCAPath + "/" + subCAName + ".crl";
                    crlFile = new FileInputStream(fileName);
                } else {
                    crlFile = CertificateManagerImpl.class.getClassLoader().getResourceAsStream(subCAName + ".crl");
                }
            } catch (final FileNotFoundException e) {
                throw new CredentialManagerCRLServiceException(e.getMessage());
            }
            if (crlFile != null) {
                try {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    return (X509CRL) certificateFactory.generateCRL(crlFile);
                } catch (final CertificateException | CRLException e) {
                    throw new CredentialManagerCRLServiceException(e.getMessage());
                }
            } else {
                return null;
            }
        } finally {
            if (crlFile != null) {
                crlFile.close();
            }
        }
    }

    @Override
    public void updateCvnOnPki()
            throws CustomConfigurationInvalidException, CustomConfigurationServiceException, CustomConfigurationAlreadyExistsException {

        log.info("calling cvn updated on pki");
        credMServiceProfilesUpdateManager.updatePkiCustomConfigurations();
    }

    @Override
    public boolean readAndCheckCvn()
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {

        log.info("calling cvn readAndCheck on pki");
        return credMServiceProfilesUpdateManager.readAndCompareCvn();
    }

    @Override
    public void cvnInit() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {

        log.info("calling cvn init");
        credMServiceProfilesUpdateManager.init();

    }

    @Override
    public void pkiCategoryDbConf(final AppCategoryXmlConfiguration xmlCategories) throws PkiCategoryMapperException {
        if (xmlCategories != null) {
            String cat;

            cat = xmlCategories.getUndefinedCategory();
            log.info("PKICategoryDbConf : pkiCategory tag Undefined = " + cat);
            try {

                if (this.getPkiConfigurationManager().isCategoryNameAvailable(cat)) {
                    EntityCategory entityCategory = new EntityCategory();
                    entityCategory.setName(cat);
                    entityCategory = this.getPkiConfigurationManager().createCategory(entityCategory); // the function
                                                                                                       // should return
                                                                                                       // the same
                                                                                                       // object passed
                                                                                                       // as input

                } else {
                    log.info("PKICategoryDbConf : pkiCategory tag Undefined " + cat + " already exists ");

                    // EntityCategory entityCategory = new EntityCategory();
                    // entityCategory.setName(cat);
                    // pkiEntityCategory=
                    // this.getPkiConfigurationManager().getCategory(
                    // entityCategory)
                    // UPGRADE CALL (entityCategory, pkiEntityCategory) // first
                    // from xml, second from db
                    //
                }
            } catch (final EntityCategoryAlreadyExistsException e) {
                log.warn("PKICategoryDbConf exception: category " + cat + " already exists"); // this should never be shown
                                                                                              // cause of
                                                                                              // isCategoryNameAvailable
                throw new PkiCategoryMapperException(e.getMessage());
            } catch (final PKIConfigurationException e) {
                log.warn("PKICategoryDbConf exception: generic PKI error during category " + cat + " creation");
                throw new PkiCategoryMapperException(e.getMessage());
            } catch (final InvalidEntityCategoryException e) {
                log.warn("PKICategoryDbConf exception: category " + cat + " has an invalid format");
                throw new PkiCategoryMapperException(e.getMessage());
            }

            cat = xmlCategories.getServiceCategory();
            log.info("PKICategoryDbConf : pkiCategory tag Service = " + cat);
            try {
                if (this.getPkiConfigurationManager().isCategoryNameAvailable(cat)) {
                    EntityCategory entityCategory = new EntityCategory();
                    entityCategory.setName(cat);
                    entityCategory = this.getPkiConfigurationManager().createCategory(entityCategory); // the function
                                                                                                       // should return
                                                                                                       // the same
                                                                                                       // object passed
                                                                                                       // as input
                } else {
                    // MONR
                    // EntityCategory entityCategory = new EntityCategory();
                    // entityCategory.setName(cat);
                    // pkiEntityCategory=
                    // this.getPkiConfigurationManager().getCategory(
                    // entityCategory)
                    // UPGRADE CALL (entityCategory, pkiEntityCategory) // first
                    // from xml, second from db
                    //
                    log.info("PKICategoryDbConf : pkiCategory tag Service " + cat + " already exists ");
                }
            } catch (final EntityCategoryAlreadyExistsException e) {
                log.warn("PKICategoryDbConf exception: category " + cat + " already exists"); // this should never be shown
                                                                                              // cause of
                                                                                              // isCategoryNameAvailable
                throw new PkiCategoryMapperException(e.getMessage());
            } catch (final PKIConfigurationException e) {
                log.warn("PKICategoryDbConf exception: generic PKI error during category " + cat + " creation");
                throw new PkiCategoryMapperException(e.getMessage());
            } catch (final InvalidEntityCategoryException e) {
                log.warn("PKICategoryDbConf exception: category " + cat + " has an invalid format");
                throw new PkiCategoryMapperException(e.getMessage());
            }

            for (final String catLoop : xmlCategories.getXmlCategories()) {
                log.info("PKICategoryDbConf : pkiCategory = " + catLoop);
                EntityCategory entityCategory = new EntityCategory();
                entityCategory.setName(catLoop);

                try {
                    if (this.getPkiConfigurationManager().isCategoryNameAvailable(catLoop)) {
                        entityCategory = this.getPkiConfigurationManager().createCategory(entityCategory); // the function
                                                                                                           // should
                                                                                                           // return
                                                                                                           // the same
                                                                                                           // object
                                                                                                           // passed as
                                                                                                           // input

                    } else {
                        log.info("PKICategoryDbConf : pkiCategory " + catLoop + " already exists ");
                        // MONR
                        // EntityCategory entityCategory = new EntityCategory();
                        // entityCategory.setName(cat);
                        // pkiEntityCategory=
                        // this.getPkiConfigurationManager().getCategory(
                        // entityCategory)
                        // UPGRADE CALL (entityCategory, pkiEntityCategory) //
                        // first from xml, second from db
                        //
                    }
                } catch (final EntityCategoryAlreadyExistsException e) {
                    log.warn("PKICategoryDbConf exception: category " + catLoop + " already exists"); // this should never be shown
                                                                                                      // cause of
                                                                                                      // isCategoryNameAvailable
                    throw new PkiCategoryMapperException(e.getMessage());
                } catch (final PKIConfigurationException e) {
                    log.warn("PKICategoryDbConf exception: generic PKI error during category " + catLoop + " creation");
                    throw new PkiCategoryMapperException(e.getMessage());
                } catch (final InvalidEntityCategoryException e) {
                    log.warn("PKICategoryDbConf exception: category " + catLoop + " has an invalid format");
                    throw new PkiCategoryMapperException(e.getMessage());
                }
            }
        }
    }

}
