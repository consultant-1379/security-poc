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
package com.ericsson.oss.itpf.security.credmservice.util;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCategoriesException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerDbUpgradeException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiCategoryMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
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

public class CredMPkiConfInitializer {

    @Inject
    PKIDbFactory pKIDbFactory;

    @Inject
    private SystemRecorderWrapper systemRecorder;

    final Properties prop = PropertiesReader.getConfigProperties();
    List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();
    List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();
    AppCategoryXmlConfiguration acxc = null;

    File root = new File(this.prop.getProperty("path.xml.pki.configuration"));
    File child = null;
    File[] brothers;
    private static final Logger log = LoggerFactory.getLogger(CredMPkiConfInitializer.class);

    private final String className = this.getClass().getSimpleName();

    /**
     * @throws CredentialManagerDbUpgradeException
     */
    public void upgrade() throws CredentialManagerDbUpgradeException {
        try {
            this.pKIDbFactory.cvnInit();
            this.caCertGenTriggerCheck();
            this.pKIDbFactory.importExtCaCertificate();
            this.pkiCatDbConf(this.root);

            this.pkiDbConf(this.root);
            this.pKIDbFactory.updateCvnOnPki();
        } catch (final Exception e) {
            log.error("Exception during Profiles and CAs Upgrade: " + e.toString()
            + " :rollback DB transaction, may be another SPS has already completed init on DB ? ");
            log.warn("exception stacktrace", e);
            this.systemRecorder.recordError("Exception during PKI DB Upgrade", ErrorSeverity.ERROR, className,
                    "DB Transactions have been rollback, may be another SPS has already completed init on DB ?", e.toString());
            throw new CredentialManagerDbUpgradeException(e);
        }

    }

    private void caCertGenTriggerCheck() {
        final Resource triggerRes = Resources.getFileSystemResource(PKIDbFactory.TRIGGERING_CA_GEN_UPD_FILE);
        this.systemRecorder.recordCommand(
                "Looking for file " + PKIDbFactory.TRIGGERING_CA_GEN_UPD_FILE + " to trigger CAs certificate generation during database upgrade on",
                CommandPhase.STARTED, className, null, null);
        if (triggerRes.exists()) {
            this.systemRecorder.recordCommand("Found file to trigger CAs certificate generation during database upgrade ", CommandPhase.ONGOING,
                    className, null, null);
            pKIDbFactory.setCAGenUpgrade(true);
            final boolean delResult = triggerRes.delete();
            this.systemRecorder.recordCommand(
                    "Deleting file to trigger CAs certificate generation during database upgrade " + " exit status: " + delResult,
                    CommandPhase.FINISHED_WITH_SUCCESS, className, null, null);
        }
    }

    private void pkiCatDbConf(final File root) throws PkiCategoryMapperException, CredentialManagerCategoriesException {

        log.debug("pkiCatDbConf : directory = {}", root.getAbsolutePath());

        final File categoryXML = new File(root.getParent() + "/PKICategories.xml");

        log.debug("Category XML File Path: {}", categoryXML.getAbsolutePath());

        try {
            this.acxc = new AppCategoryXmlConfiguration(categoryXML);
        } catch (final CredentialManagerCategoriesException e1) {
            log.error("pkiCatDbConf during AppCategoryXmlConfiguration received exception: {}", e1.toString());
            throw e1;
        }
        try {
            this.pKIDbFactory.pkiCategoryDbConf(acxc);
        } catch (final PkiCategoryMapperException e) {
            log.error("pkiCatDbConf during pkiCategoryDbConf received exception: {}", e.toString());
            throw e;
        }
    }

    private void pkiDbConf(final File root) throws CredentialManagerDbUpgradeException {

        log.debug("pkiDbConf : directory = {}", root.getAbsolutePath());

        this.brothers = this.findDirectories(root);

        for (final File dir : this.brothers) {

            if (dir.getName().toLowerCase().equals("entities")) {
                try {
                    this.getEntitiesConf(dir);
                } catch (final CredentialManagerEntitiesException e) {
                    // log and printstack for this exception are in the called method getEntitiesConf
                    throw new CredentialManagerDbUpgradeException(e);
                }
                log.debug("pkiDbConf : entity directoryChild = {}", dir.getName());
            }

            else if (dir.getName().toLowerCase().equals("profiles")) {
                try {
                    this.getProfilesConf(dir);
                } catch (final CredentialManagerProfilesException e) {
                    // log and printstack for this exception are in the called method getProfilesConf
                    throw new CredentialManagerDbUpgradeException(e);
                }
                log.debug("pkiDbConf : profile directoryChild = {}", dir.getName());
            }

            else if (dir.getName().toLowerCase().startsWith("enm")) {
                this.child = dir;
                log.debug("pkiDbConf : enm directoryChild = {}", dir.getName());
            }
        }

        if (this.child != null && (this.appProfXConfList.size() > 0 || this.appEntXConfList.size() > 0)) {
            try {
                this.pKIDbFactory.PKIDbConf(this.appProfXConfList, this.appEntXConfList);
            } catch (PkiProfileMapperException | PkiEntityMapperException | CANotFoundException | ProfileServiceException | EntityServiceException
                    | ProfileNotFoundException | EntityNotFoundException | CertificateExtensionException | InvalidSubjectException
                    | MissingMandatoryFieldException | UnSupportedCertificateVersion | AlgorithmNotFoundException | EntityCategoryNotFoundException
                    | RevokedCertificateException | ExpiredCertificateException | InvalidCAException | InvalidEntityCategoryException
                    | CertificateGenerationException | CertificateServiceException | InvalidProfileAttributeException | ProfileAlreadyExistsException
                    | EntityAlreadyExistsException | InvalidEntityAttributeException | InvalidProfileException | UnsupportedCRLVersionException
                    | CRLExtensionException | InvalidCRLGenerationInfoException | IOException | InvalidEntityException | CRLGenerationException e) {

                log.error("Received Exception on pkiDbConf ", e);
                throw new CredentialManagerDbUpgradeException(e);
            } finally {
                this.appProfXConfList.clear();
                this.appEntXConfList.clear();
            }
        }

        if (this.brothers.length < 3 && this.child != null) {
            this.child = null;
        }

        if (this.child != null) {
            this.pkiDbConf(this.child);
        }

    }

    public void getProfilesConf(final File dir) throws CredentialManagerProfilesException {

        final File[] filesNameList = this.findFiles(dir);
        AppProfileXmlConfiguration apxc;
        for (final File file : filesNameList) {
            try {
                apxc = new AppProfileXmlConfiguration(file);
                this.appProfXConfList.add(apxc);

            } catch (final CredentialManagerProfilesException e) {
                log.error("Received exception on getProfilesConf ", e);
                throw e;
            }
        }

    }

    public void getEntitiesConf(final File dir) throws CredentialManagerEntitiesException {
        final File[] filesNameList = this.findFiles(dir);
        AppEntityXmlConfiguration aexc;
        for (final File file : filesNameList) {
            try {
                aexc = new AppEntityXmlConfiguration(file);
                this.appEntXConfList.add(aexc);
            } catch (final CredentialManagerEntitiesException e) {
                log.error("Received exception on getEntitiesConf ", e);
                throw e;
            }

        }
    }

    public File[] findFiles(final File dir) {
        return dir.listFiles(new XmlFileFilter() {

            @Override
            public boolean acceptXml(final File f) {
                return f.isFile();
            }
        });
    }

    public File[] findDirectories(final File root) {
        return root.listFiles(new FileFilter() {

            @Override
            public boolean accept(final File f) {
                return f.isDirectory();
            }
        });
    }

    public List<AppProfileXmlConfiguration> getAppProfXConfList() {
        return this.appProfXConfList;
    }

    public List<AppEntityXmlConfiguration> getAppEntXConfList() {
        return this.appEntXConfList;
    }

    public void checkDbCvnStatus() {

        try {
            if (this.pKIDbFactory.readAndCheckCvn() == true) {
                log.warn("Received exception during db upgrade but most probabily everthing is fine, cvn check result is true");
            } else {
                log.warn("Received exception during db upgrade and cvn check result is false");
            }
        } catch (CustomConfigurationNotFoundException | CustomConfigurationInvalidException | CustomConfigurationServiceException e) {
            log.error("Received exception during CheckCvn: " + e.getMessage());
        }
    }
}
