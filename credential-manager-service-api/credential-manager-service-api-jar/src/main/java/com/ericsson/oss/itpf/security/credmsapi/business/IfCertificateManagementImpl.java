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
package com.ericsson.oss.itpf.security.credmsapi.business;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapperFactory;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmsapi.JNDIResolver;
import com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement;
import com.ericsson.oss.itpf.security.credmsapi.api.InternalIfCredentialManagement;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateValidationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.Subject;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustSource;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.SANConvertHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CertificateRevocationListUtils;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerRevocationUtils;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialReaderFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;

public class IfCertificateManagementImpl implements IfCertificateManagement, InternalIfCredentialManagement {

    // /ericsson/tor/data/credm/conf/credentialManagerConfigurator.properties
    private final String GLOBAL_CREDMA_OPTION_FILE = "globalConfigurationFilename";
    private final String FORCE_RENEWAL = "forceCertificateRenewal";

    // private static final Logger LOG = LoggerFactory
    // .getLogger(IfCertificateManagementImpl.class);
    private static final Logger LOG = LogManager.getLogger(IfCertificateManagementImpl.class);

    private CredMServiceWrapperFactory credMServiceWrapperFactory = null;

    /**
     *
     */
    public IfCertificateManagementImpl() {
        // make this way to avoid final declaration (mockito doesn't support
        // final objects)
        this.credMServiceWrapperFactory = new CredMServiceWrapperFactory();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# getCredentialManagerInterfaceVersion()
     */
    @Override
    public String getCredentialManagerInterfaceVersion() {

        // retrieve the version
        final JNDIResolver propertyReader = new JNDIResolver();
        final String version = propertyReader.getInterfaceVersion();
        return version;
    }

    /*
     * issueCertificate
     *
     * called by ENIS or other services
     *
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# issueCertificate
     * (com.ericsson.oss.itpf.security.credmsapi.api.model.entityInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo)
     */
    @Override
    public Boolean issueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo)
            throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException, OtpExpiredException {

        return this.issueCertificateForEnis(entityInfo, ksInfo, false);

    } // end of issueCertificate (for ENIS)

    /**
     * @param entityInfo
     * @param ksInfo
     * @return
     * @throws IssueCertificateException
     * @throws EntityNotFoundException
     * @throws InvalidCertificateFormatException
     */
    private Boolean issueCertificateForEnis(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final boolean chain)
            throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException, OtpExpiredException {
        /**
         * Check input parameters validity
         */
        this.issueCertFromEnisCheckInput(entityInfo, ksInfo);

        LOG.info("Issuing Certificate for ENTITY= " + entityInfo.getEntityName());

        /**
         * Get remote object
         */
        final CredMServiceWrapper serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL,
                false);

        /**
         * Get Entity params: entityName
         */
        final CredentialManagerEntity entity = serviceWrapper.getEntity(entityInfo.getEntityName());

        if (entity == null) {
            serviceWrapper.printErrorOnSystemRecorder("Entity get FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityInfo.getEntityName(), null);
            throw (new EntityNotFoundException("Entity " + entityInfo.getEntityName() + " does not exist"));
        }

        /**
         * Get Profile params: endEntityProfileName
         */
        final CredentialManagerProfileInfo profileInfo = serviceWrapper.getProfile(entity.getEntityProfileName());

        if (profileInfo == null) {
            serviceWrapper.printErrorOnSystemRecorder("Profile get FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entity.getEntityProfileName(), null);
            throw (new IssueCertificateException("Error occurred while retrieving " + entity.getEntityProfileName() + " profile"));
        }

        // Decision: validity check is not necessary for external ENIS/SLS user

        /**
         * Create Key Pair Create CSR Get Certificate
         */
        final CertificateManager certificateManager = new CertificateManager(serviceWrapper);

        try {
            certificateManager.generateKey(profileInfo);
            certificateManager.generateCSR(entity, profileInfo, null);
            // request for the single certificate without its complete chain
            certificateManager.generateCertificate(entityInfo.getEntityName(), profileInfo, chain, entityInfo.getOneTimePassword());
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Certificate write FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityInfo.getEntityName(), "exception");
            throw (new IssueCertificateException(e.getMessage()));
        }

        /*
         * Create a keystoreInfo list
         */

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        ksInfoList.add(ksInfo);

        // TODO and the clear truststore ??

        /*
         * Create Trust store info
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo(ksInfo.getKeyAndCertLocation(), "",
                StorageFormatUtils.convertCertToTrustFormat(ksInfo.getCertFormat()), ksInfo.getKeyStorePwd(), ksInfo.getAlias(), TrustSource.BOTH);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * get and write Trust
         */
        final TrustManager trustManager = new TrustManager(serviceWrapper);
        try {
            /**
             * wipe out Trust data
             */
            // trustManager.clearTruststores(tsInfoList);
            /**
             * get Trusts
             */
            trustManager.retrieveTrust(entity.getEntityProfileName());
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Trust get FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entity.getEntityProfileName(), null);
            throw (new IssueCertificateException(e.getMessage()));
        }

        /**
         * Remove key store file to clean current key store info. This is done here so that we are sure to have got new data about certificate and
         * trusts
         */
        final File file = new File(ksInfo.getKeyAndCertLocation());
        file.delete();

        try {
            /**
             * write Key and Certificate
             */
            certificateManager.writeKeyAndCertificate(ksInfoList);
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Certificate write FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityInfo.getEntityName(), "exception");
            throw (new IssueCertificateException(e.getMessage()));
        }

        serviceWrapper.printCommandOnSystemRecorder("Certificate write SUCCESS", CommandPhase.FINISHED_WITH_SUCCESS, "credential-manager-service-api",
                entityInfo.getEntityName(), null);

        try {
            /**
             * Write Trusts
             */
            trustManager.writeTrust(tsInfoList);
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Trust write FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entity.getEntityProfileName(), null);
            throw (new IssueCertificateException(e.getMessage()));
        }

        serviceWrapper.printCommandOnSystemRecorder("Trust write SUCCESS (Check)", CommandPhase.FINISHED_WITH_SUCCESS,
                "credential-manager-service-api", entity.getEntityProfileName(), null);

        // TODO CRL ????

        return true;
    }

    /**
     * issueCertificate
     *
     * called with data read form a XML
     *
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# issueCertificate(java.lang.String, java.lang.String,
     *      com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo)
     */
    @Override
    public Boolean issueCertificate(final String entityName, final String distinguishName, final SubjectAlternativeNameType subjectAltName,
                                    final String entityProfileName, final List<KeystoreInfo> ksInfoList, final List<TrustStoreInfo> tsInfoList,
                                    final List<TrustStoreInfo> crlInfoList, final CredentialManagerCertificateExtension certExtension,
                                    final boolean certificateChain)
            throws IssueCertificateException {

        final boolean isInstall = true;
        final boolean result = this.issueCertificateAndTrust(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList,
                crlInfoList, certExtension, certificateChain, isInstall, false);
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# issueCertificate(java.lang.String, java.lang.String,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo)
     */
    @Override
    public Boolean issueCertificateRESTchannel(final String entityName, final String distinguishName, final SubjectAlternativeNameType subjectAltName,
                                               final String entityProfileName, final List<KeystoreInfo> ksInfoList,
                                               final List<TrustStoreInfo> tsInfoList, final List<TrustStoreInfo> crlInfoList,
                                               final CredentialManagerCertificateExtension certificateExtensionInfo, final boolean infiniteLoop,
                                               final boolean isCheck, final boolean firstDayRun)
            throws IssueCertificateException {

        /**
         * Check input parameters validity
         */
        this.issueCertFromXMLCheckInput(entityName, distinguishName, entityProfileName, ksInfoList, tsInfoList, crlInfoList);

        LOG.info("issueCertificate REST channel END ENTITY=" + entityName);

        /**
         * get rest service
         */
        final CredMServiceWrapper serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.REST_CHANNEL,
                infiniteLoop);
        // final CredentialManagerServiceRestClient restClient = new
        // CredentialManagerServiceRestClient(addr);

        /**
         * Get Profile params: endEntityProfileName No parameter CredMServices already know that is for CredMCLI
         */
        final CredentialManagerProfileInfo profileInfo = serviceWrapper.getProfile();

        if (profileInfo == null) {
            serviceWrapper.printErrorOnSystemRecorder("Profile get FAILURE (Rest)", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityProfileName, null);
            throw (new IssueCertificateException("ProfileInfo is NULL"));
        }

        /**
         * Get and Create Entity params: entityName must contains the hostname where CredMCLI is running
         *
         * The REST channel doesn't manage the distinguishName (entityName only)
         */
        CredentialManagerEntity entity = null;
        try {
            entity = serviceWrapper.createAndGetEndEntity(entityName, "");
            if (entity == null) {
                serviceWrapper.printErrorOnSystemRecorder("Entity create FAILURE (Rest)", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entityName, "entity null");
                throw (new IssueCertificateException("Entity is NULL"));
            }
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Entity create FAILURE (Rest)", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityName, "exception");
            throw (new IssueCertificateException(e.getMessage()));
        }

        final CertificateManager certificateManager = new CertificateManager(serviceWrapper);

        /**
         * check certificate validity
         */
        boolean certValid = true;

        final CredentialManagerPIBParameters parameters = serviceWrapper.getPibParameters();

        // here we can force the failure of the test and then the renewal of all the certificates
        // only if the credentialmanagercli is runing with -i option
        if (!isCheck) {
            certValid = this.updateCertValid();
        }

        if (certValid) {
            for (final KeystoreInfo ksInfo : ksInfoList) {
                try {
                    certValid = certValid && certificateManager.checkCertificateValidity(ksInfo, "CN=" + entityName, entity, firstDayRun, parameters);
                } catch (final CertificateValidationException e) {
                    serviceWrapper.printErrorOnSystemRecorder("Certificate check FAILURE (Rest)", ErrorSeverity.ERROR,
                            "credential-manager-service-api", entityName, "exception");
                    throw (new IssueCertificateException("Checking certificate validation exception : " + e.getMessage()));
                }
            }
        }
        if (!certValid) {

            try {
                /**
                 * delete old keystore
                 */
                certificateManager.clearKeystores(ksInfoList);

                /**
                 * Create Key Pair Create CSR Get Certificate
                 */
                LOG.info("Regenerate CERTIFICATE for " + entityName);
                serviceWrapper.printCommandOnSystemRecorder("Regenerating Certificate (Rest)", CommandPhase.STARTED, "credential-manager-service-api",
                        entityName, null);
                System.out.println("Regenerate CERTIFICATE for " + entityName);

                certificateManager.generateKey(profileInfo);
                certificateManager.generateCSR(entity, profileInfo, certificateExtensionInfo);
                certificateManager.generateCertificateRestChannel();

                /**
                 * write Key and Certificate
                 */
                certificateManager.writeKeyAndCertificate(ksInfoList);
            } catch (final IssueCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("Certificate write FAILURE (Rest)", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entityName, "exception");
                throw (new IssueCertificateException(e.getMessage()));
            }

            serviceWrapper.printCommandOnSystemRecorder("Certificate write SUCCESS (Rest)", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api", entityName, null);
        }

        final TrustManager trustManager = new TrustManager(serviceWrapper);
        // isCheck true: CommandOwnCert was issued by CommandCheck, so it checks
        // truststores validity and update it if neede
        if (isCheck) {

            final Boolean checkResult = this.checkAndUpdateTrusts(entityName, entityProfileName, tsInfoList, true);
            LOG.info("issueCertificate REST channel, checkAndUpdateTrusts result " + checkResult);

        } else {

            /**
             * in install phase we always update the trust
             */
            try {
                /**
                 * wipe out Trust data
                 */
                trustManager.clearTruststores(tsInfoList);
                /**
                 * get and write Trust
                 */
                trustManager.retrieveTrust(entity.getEntityProfileName());
                trustManager.writeTrust(tsInfoList);
            } catch (final IssueCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("Trust write FAILURE (Rest)", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entity.getEntityProfileName(), null);
                throw (new IssueCertificateException(e.getMessage()));
            }

            serviceWrapper.printCommandOnSystemRecorder("Trust write SUCCESS (Rest)", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api", entity.getEntityProfileName(), null);
        }
        /**
         * CRL is not managed under REST CHANNEL
         */

        return true;

    } // end of issueCertificateRESTchannel

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# reIssueCertificate
     * (com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean reIssueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final CrlReason revocationReason)
            throws ReissueCertificateException, EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException,
            OtpExpiredException {

        this.innerReissueCertificate(entityInfo, ksInfo, revocationReason, false);

        return true;
    }

    /**
     * @param entityInfo
     * @param ksInfo
     * @param revocationReason
     * @throws EntityNotFoundException
     * @throws InvalidCertificateFormatException
     * @throws OtpNotValidException
     * @throws OtpExpiredException
     * @throws ReissueCertificateException
     */
    private void innerReissueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final CrlReason revocationReason,
                                         final boolean chain)
            throws EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException, OtpExpiredException,
            ReissueCertificateException {
        // Retrieve present certificate identifier to be subsequently revoked
        final CredentialManagerCertificateIdentifier certificateIdentifer = CertificateUtils.retrieveCertificateId(ksInfo);

        // Issue a certificate
        try {
            this.issueCertificateForEnis(entityInfo, ksInfo, chain);
        } catch (final IssueCertificateException e) {
            LOG.error("Error while reissuing a certificate for entity " + entityInfo.getEntityName());
            throw (new ReissueCertificateException("Error while reissuing a certificate for entity " + entityInfo.getEntityName()));
        }

        /**
         * Get remote object
         */
        CredMServiceWrapper serviceWrapper;
        try {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, true);
        } catch (final IssueCertificateException e) {
            throw new ReissueCertificateException(e.getMessage());
        }

        // Revoke previous certificate, if any
        if (certificateIdentifer != null) {

            try {
                final CredentialManagerRevocationReason cmRevocationReason = CredentialManagerRevocationUtils
                        .convertRevocationReason(revocationReason);
                if (serviceWrapper.revokeCertificateById(certificateIdentifer, cmRevocationReason, new Date())) {
                    // success
                    serviceWrapper.printCommandOnSystemRecorder("Certificate revoke SUCCESS", CommandPhase.FINISHED_WITH_SUCCESS,
                            "credential-manager-service-api", entityInfo.getEntityName(), null);
                } else {
                    // failure
                    serviceWrapper.printCommandOnSystemRecorder("Certificate revoke FAILURE", CommandPhase.FINISHED_WITH_ERROR,
                            "credential-manager-service-api", entityInfo.getEntityName(), null);
                }
            } catch (final CredentialManagerInternalServiceException | CredentialManagerExpiredCertificateException
                    | CredentialManagerAlreadyRevokedCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("Certificate revoke FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entityInfo.getEntityName(), "exception");
                throw new ReissueCertificateException(e.getMessage());
            } catch (final CredentialManagerCertificateNotFoundException e) {
                LOG.info("credential-manager-service-api: Certificate Not Found for entity = " + entityInfo.getEntityName());
            }
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# revokeCertificate
     * (com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean revokeCertificate(final EntityInfo entityInfo, final CrlReason revocationReason)
            throws RevokeCertificateException, EntityNotFoundException {

        if (entityInfo == null || entityInfo.getEntityName() == null || entityInfo.getEntityName().isEmpty()) {
            LOG.error("EntityInfo not valid: object is null or entityName is null");
            throw (new RevokeCertificateException("EntityInfo not valid: object is null or entityName is null"));
        }

        if (revocationReason == null) {
            LOG.error("RevocationReason not valid: it cannot be null");
            throw (new RevokeCertificateException("RevocationReason not valid: it cannot be null"));
        }

        /**
         * Get remote object
         */
        CredMServiceWrapper serviceWrapper;
        try {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, true);
        } catch (final IssueCertificateException e) {
            LOG.error("revokeCertificate ERROR: buildServiceWrapper failed");
            throw (new RevokeCertificateException("revokeCertificate: buildServiceWrapper failed"));
        }

        try {
            serviceWrapper.revokeCertificateByEntity(entityInfo.getEntityName(),
                    CredentialManagerRevocationUtils.convertRevocationReason(revocationReason), Calendar.getInstance().getTime());
        } catch (final RevokeCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Certificate revoke FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityInfo.getEntityName(), "revoke error");
            throw new RevokeCertificateException(e.getMessage());
        } catch (final EntityNotFoundException e) {
            serviceWrapper.printErrorOnSystemRecorder("Certificate revoke FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    entityInfo.getEntityName(), "entity not found");
            throw new EntityNotFoundException(e.getMessage());
        }

        serviceWrapper.printCommandOnSystemRecorder("Certificate revoke SUCCESS", CommandPhase.FINISHED_WITH_SUCCESS,
                "credential-manager-service-api", entityInfo.getEntityName(), null);

        return true;
    }

    /**
     * checkAndUpdateCertificate
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.InternalIfCredentialManagement#checkAndUpdateCertificate(java.lang.String, java.lang.String,
     *      com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType, java.lang.String, java.util.List,
     *      com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension, boolean)
     */
    @Override
    public Boolean checkAndUpdateCertificate(final String entityName, final String distinguishName, final SubjectAlternativeNameType subjectAltName,
                                             final String entityProfileName, final List<KeystoreInfo> ksInfoList,
                                             final CredentialManagerCertificateExtension certificateExtensionInfo, final boolean certificateChain,
                                             final boolean firstDailyRun)
            throws IssueCertificateException {

        final boolean isInstall = false;
        final List<TrustStoreInfo> tsInfoList = null;
        final List<TrustStoreInfo> crlInfoList = null;
        final boolean result = this.issueCertificateAndTrust(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList,
                crlInfoList, certificateExtensionInfo, certificateChain, isInstall, firstDailyRun);
        return result;
    }

    /*
     * checkAndUpdateTrusts for entity and EntityProfile
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement# checkAction(java.lang.String, java.lang.String,
     * com.ericsson.oss.itpf.security .credmsapi.api.model.SubjectAlternativeNameType, java.lang.String, java.util.List, java.util.List,
     * java.util.List, com.ericsson.oss.itpf.security .credmsapi.api.model.CredentialManagerCertificateExtension)
     */
    @Override
    public Boolean checkAndUpdateTrusts(final String entityName, final String entityProfileName, final List<TrustStoreInfo> tsInfoList,
                                        final boolean isOwn)
            throws IssueCertificateException {

        String profileName = entityProfileName;
        CredMServiceWrapper serviceWrapper;

        if (isOwn) {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.REST_CHANNEL, false);
            // serviceWrapper =
            // this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL,
            // false);
            // in this case credmaCLI can try the REST channel
            // if (serviceWrapper == null) {
            // serviceWrapper =
            // this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.REST_CHANNEL,
            // false);
            // }
        } else {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, false);
            // update the profileName
            profileName = serviceWrapper.getEntity(entityName).getEntityProfileName();
        }

        return this.innerCheckTrust(profileName, CredentialManagerProfileType.ENTITY_PROFILE, tsInfoList, serviceWrapper);

    } // end of CheckTrusts

    /**
     * checkAndUpdateTrusts for TrustProfile
     *
     */
    @Override
    public Boolean checkAndUpdateTrustsTP(final String trustProfileName, final List<TrustStoreInfo> tsInfoList) throws IssueCertificateException {

        final CredMServiceWrapper serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL,
                false);

        return this.innerCheckTrust(trustProfileName, CredentialManagerProfileType.TRUST_PROFILE, tsInfoList, serviceWrapper);

    } // end of CheckTrusts

    /**
     * innerCheckTrust
     *
     * @param entityName
     * @param tsInfoList
     * @param profileName
     * @param serviceWrapper
     * @param retrievedTrusts
     * @return
     * @throws IssueCertificateException
     */
    private Boolean innerCheckTrust(final String profileName, final CredentialManagerProfileType profileType, final List<TrustStoreInfo> tsInfoList,
                                    final CredMServiceWrapper serviceWrapper)
            throws IssueCertificateException {

        CredentialManagerTrustMaps retrievedTrusts = null;

        for (final TrustStoreInfo trustStoreInfo : tsInfoList) {
            LOG.debug("Truststore file location: " + trustStoreInfo.getTrustFolder() + trustStoreInfo.getTrustFileLocation());
            final CredentialReaderFactory credRF = new CredentialReaderFactory();
            final SortedSet<CredentialManagerCertificateIdentifier> trustStoreIdentifiers = new TreeSet<CredentialManagerCertificateIdentifier>();
            boolean allCertsValid = true; // this flag will be used to check
                                          // credmaCLI trusts

            CredentialReader credRTS = null;
            try {
                credRTS = credRF.getCredentialreaderInstance(StorageFormatUtils.getTrustFormatString(trustStoreInfo.getCertFormat()),
                        trustStoreInfo.getTrustFolder(), trustStoreInfo.getTrustFileLocation(), trustStoreInfo.getTrustStorePwd());
            } catch (final StorageException e) {
                LOG.error("CredentialReader Instance is NULL or empty");
                throw (new IssueCertificateException("CredentialReader Instance is NULL or empty"));
            }
            try {
                final Set<Certificate> certs = credRTS.getAllCertificates(trustStoreInfo.getAlias());
                for (final Certificate cert : certs) {
                    final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                    final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);

                    System.out.println("read TRUST : " + trustStoreInfo.getAlias() + " from " + certificate.getSubjectDN());

                    /**
                     * Validity Period (only for the certificates that cant be checked by credma service)t
                     */
                    try {
                        certificate.checkValidity();
                    } catch (final Exception e) {
                        // the trust certificate is not more valid
                        // i know, its not a full check, a more complete test is
                        // performed in the next lines
                        // calling the credma service, but using REST channel
                        // this is not possible
                        allCertsValid = false;
                    }

                    //
                    final CredentialManagerCertificateIdentifier certId = CertificateUtils.buildIdentifier(certificate);
                    trustStoreIdentifiers.add(certId);

                } // end of for certificates
            } catch (StorageException | CertificateException e) {
                LOG.info("File not found or corrupted:" + trustStoreInfo.getTrustFolder() + trustStoreInfo.getTrustFileLocation());
                // there is no trusts
                allCertsValid = false;

            }

            if (!allCertsValid) {
                // retrieve the trust list to write it
                retrievedTrusts = serviceWrapper.getTrustCertificates(profileName, profileType);

            } else {
                // check the service about trust validity (note that in case of
                // REST it will return an empty list
                retrievedTrusts = serviceWrapper.checkCurrentTrust(profileName, profileType, trustStoreIdentifiers, trustStoreInfo.getTrustSource());
            }

            // after all these, if the trust must be updated, the
            // retrievedTrusts contains the new ones
            if (retrievedTrusts != null) { // atleast one truststore needs
                                               // re-writing, so it does that to
                                           // all of them
                break;
            }
            LOG.info("Trust is valid: nothing to be done for " + profileName);
            System.out.println("Trust is valid: nothing to be done for " + profileName);

        } // end of for trustinfo

        if (retrievedTrusts == null) {
            LOG.info("Nothing to do for All truststores for " + profileName);
            // false mean that nothing has been done
            return false;
        }

        LOG.info("ReWrite Trust for " + profileName);
        System.out.println("ReWrite Trust for " + profileName);

        final TrustManager trustManager = new TrustManager(serviceWrapper);
        try {
            /**
             * wipe out Trust data
             */
            // trustManager.cleanTruststore(tsInfoList, ksInfoList);
            trustManager.clearTruststores(tsInfoList);
            /**
             * get and write Trust
             */
            trustManager.setTrustMaps(retrievedTrusts);
            trustManager.writeTrust(tsInfoList);
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Trust write FAILURE (Check)", ErrorSeverity.ERROR, "credential-manager-service-api",
                    profileName, null);
            throw (new IssueCertificateException(e.getMessage()));
        }

        serviceWrapper.printCommandOnSystemRecorder("Trust write SUCCESS (Check)", CommandPhase.FINISHED_WITH_SUCCESS,
                "credential-manager-service-api", profileName, null);
        // true means that some actions has been done
        return true; // TODO: DU managed LOG and Exception in case of error

    } // end of innerCheckTrust

    /*
     * (non-Javadoc)
     *
     * API for checking certificate validity in the CRLstore and reissue of the CRL if needed RETURN: boolean: FALSE if nothing to DO TRUE (changed
     * certificates)
     */
    @Override
    public Boolean checkAndUpdateCRL(final String entityName, final List<TrustStoreInfo> crlInfoList, final boolean forceUpdate)
            throws IssueCertificateException {

        final CredMServiceWrapper serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL,
                false);
        // update the profileName
        final String entityProfileName = serviceWrapper.getEntity(entityName).getEntityProfileName();

        return this.innerCheckAndUpdateCRL(entityProfileName, CredentialManagerProfileType.ENTITY_PROFILE, crlInfoList, forceUpdate);
    }

    /*
     * (non-Javadoc)
     *
     * API for checking certificate validity in the CRLstore and reissue of the CRL if needed RETURN: boolean: FALSE if nothing to DO TRUE (changed
     * certificates)
     */
    @Override
    public Boolean checkAndUpdateCRL_TP(final String trustProfileName, final List<TrustStoreInfo> crlInfoList, final boolean forceUpdate)
            throws IssueCertificateException {

        return this.innerCheckAndUpdateCRL(trustProfileName, CredentialManagerProfileType.TRUST_PROFILE, crlInfoList, forceUpdate);
    }

    /**
     * innerCheckAndUpdateCRL
     *
     * @param entityProfileName
     * @param profileType
     * @param crlInfoList
     * @param forceUpdate
     * @return
     * @throws IssueCertificateException
     */
    private Boolean innerCheckAndUpdateCRL(final String profileName, final CredentialManagerProfileType profileType,
                                           final List<TrustStoreInfo> crlInfoList, final boolean forceUpdate)
            throws IssueCertificateException {
        /**
         * Get remote object
         */
        final CredMServiceWrapper serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL,
                true);
        final CrlManager crlManager = new CrlManager(serviceWrapper);

        final CredentialReaderFactory credRF = new CredentialReaderFactory();
        // this flag means we have to update the crl store
        boolean flagRenew = forceUpdate;
        CredentialManagerCrlMaps retrievedCrls = null;

        if (!flagRenew) {
            for (final TrustStoreInfo crlInfo : crlInfoList) {
                final SortedSet<CredentialManagerCRLIdentifier> CrlIdentifiers = new TreeSet<CredentialManagerCRLIdentifier>();
                CredentialReader crlReader = null; // getCsrFormatString(crlInfo.getCertFormat())
                try {
                    crlReader = credRF.getCredentialreaderInstance(StorageFormatUtils.getTrustFormatString(crlInfo.getCertFormat()),
                            crlInfo.getTrustFolder(), crlInfo.getTrustFileLocation(), crlInfo.getTrustStorePwd());

                } catch (final StorageException e) {
                    LOG.error("CredentialReader Instance is NULL or empty");
                    throw (new IssueCertificateException("CredentialReader Instance is NULL or empty"));
                }

                try {
                    // read from the file all the CRLs
                    Set<CRL> crlSet = crlReader.getCRLs(crlInfo.getAlias());
                    // check for missing or wrong file
                    if (crlSet == null) {
                        crlSet = new HashSet<CRL>();
                    }
                    if (crlSet.isEmpty()) {
                        flagRenew = true;
                        LOG.info("CheckCRLs: missing or wrong file for " + crlInfo.getAlias());
                    }

                    for (final CRL crl : crlSet) {
                        // we skip the local date test due to external crl that can already expired on cred
                        LOG.info("Preparing crl list in order to verify them");
                        if (crl.getType().equals("X.509")) {
                            final X509CRL xcrl = (X509CRL) crl;
                            //    if (CertificateRevocationListUtils.checkDateValidity(xcrl)) {
                            final CredentialManagerCRLIdentifier crlId = CertificateRevocationListUtils.buildIdentifier(xcrl);
                            CrlIdentifiers.add(crlId);
                            //  } else {
                            //      flagRenew = true;
                            //      LOG.info("CRL date local check found different CRLs");
                        }
                    }

                    if (flagRenew) {
                        retrievedCrls = serviceWrapper.getCRLs(profileName, profileType);
                    } else {
                        retrievedCrls = serviceWrapper.compareCRLsAndRetrieve(profileName, profileType, CrlIdentifiers, crlInfo.getTrustSource());
                        // like trusts, in case of multiple crlInfo locations, if one of them has to be rewritten it will rewrite 'em all
                        if (retrievedCrls != null) {
                            flagRenew = true;
                        }
                    }
                } catch (final StorageException e) { //NOSONAR
                    LOG.error("CredentialReader StorageException : " + e.getMessage());
                    throw (new IssueCertificateException("CredentialReader StorageException"));
                } catch (final IssueCertificateException e) {
                    serviceWrapper.printErrorOnSystemRecorder("CRL get FAILURE (Check)", ErrorSeverity.ERROR, "credential-manager-service-api",
                            profileName, null);
                    throw (new IssueCertificateException(e.getMessage())); 
                }
            } // end of for crlInfoList
        } // end of if ! flagRenew
        else {
            retrievedCrls = serviceWrapper.getCRLs(profileName, profileType);
        }

        if (retrievedCrls != null) {
            try {
                crlManager.clearCrlStore(crlInfoList);
                crlManager.setCaCrlMaps(retrievedCrls);
                crlManager.writeCrlList(crlInfoList);
            } catch (final IssueCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("CRL write FAILURE (Check)", ErrorSeverity.ERROR, "credential-manager-service-api",
                        profileName, null);
                throw (new IssueCertificateException(e.getMessage()));
            }
            serviceWrapper.printCommandOnSystemRecorder("CRL write SUCCESS (Check)", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api", profileName, null);
            return true; // crl updated
        } else if (flagRenew) {
            LOG.warn("checkAndUpdateCRL flag to update was true but no CLR:s has been received for  " + profileName);
        }

        LOG.info("Crl is valid: nothing to be done for " + profileName);
        System.out.println("Crl is valid: nothing to be done for " + profileName);

        return false; // nothing done

    } // end of checkAndUpdateCRL

    @Override
    public List<EntitySummary> getEndEntitiesByCategory(final String category)
            throws GetEndEntitiesByCategoryException, InvalidCategoryNameException {

        /**
         * in this case the method is called outside the CredentialManager, the internal exception must be catched and reported as
         * GetEndEntitiesByCategoryException
         */
        CredMServiceWrapper serviceWrapper;
        try {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, true);
        } catch (final IssueCertificateException e) {
            throw new GetEndEntitiesByCategoryException(e);
        }

        //
        // call the Service bean, with the exception traslation
        //
        Set<CredentialManagerEntity> entitySet = null;
        try {
            entitySet = serviceWrapper.getEntitiesSummaryByCategory(category);
        } catch (final CredentialManagerInvalidArgumentException e) {
            serviceWrapper.printErrorOnSystemRecorder("Entities by Category get FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    category, "invalid argument");
            LOG.error(ErrorMsg.API_ERROR_SERVICE_CATEGORY_NOT_FOUND, category);
            throw new InvalidCategoryNameException(e);
        } catch (final CredentialManagerInternalServiceException e) {
            serviceWrapper.printErrorOnSystemRecorder("Entities by Category get FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    category, "internal exception");
            LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_ENTITY_BY_CATEGORY, category);
            throw new GetEndEntitiesByCategoryException(e);
        }

        //
        // build the Summary list
        //
        final List<EntitySummary> entitySummaryList = new ArrayList<EntitySummary>();
        if (entitySet != null) {

            for (final CredentialManagerEntity entity : entitySet) {

                try {
                    final CredentialManagerEntityStatus CMstatus = entity.getEntityStatus();
                    final CredentialManagerSubject CMsubject = entity.getSubject();
                    final EntitySummary summary = new EntitySummary(entity.getName(), EntityStatus.valueOf(CMstatus.toString()),
                            this.buildSubject(CMsubject));

                    entitySummaryList.add(summary);
                } catch (final Exception e) {
                    serviceWrapper.printErrorOnSystemRecorder("Entities by Category get FAILURE", ErrorSeverity.ERROR,
                            "credential-manager-service-api", category, "summary list exception");
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_ENTITY_BY_CATEGORY, category);
                    throw new GetEndEntitiesByCategoryException(e);
                }
            }
        }

        serviceWrapper.printCommandOnSystemRecorder("Entities by Category get SUCCESS", CommandPhase.FINISHED_WITH_SUCCESS,
                "credential-manager-service-api", category, null);
        return entitySummaryList;

    } // end of getEndEntitiesByCategory

    //
    // PRIVATE
    //

    /**
     * issueCertificateAndTrust (called by issueCertificate and checkAndUpdateCertificate)
     *
     * @param entityName
     * @param distinguishName
     * @param subjectAltName
     * @param entityProfileName
     * @param ksInfoList
     * @param tsInfoList
     * @param crlInfoList
     * @param certificateExtensionInfo
     * @param certificateChain
     * @param isInstall
     * @return
     * @throws IssueCertificateException
     */
    private Boolean issueCertificateAndTrust(final String entityName, final String distinguishName, final SubjectAlternativeNameType subjectAltName,
                                             final String entityProfileName, final List<KeystoreInfo> ksInfoList,
                                             final List<TrustStoreInfo> tsInfoList, final List<TrustStoreInfo> crlInfoList,
                                             final CredentialManagerCertificateExtension certificateExtensionInfo, final boolean certificateChain,
                                             final boolean isInstall, final boolean firstDailyRun)
            throws IssueCertificateException {

        /**
         * this part is in common between issueCertificate (install phase reading XML file) and checkAndUpdateCertificate (check phase) in the first
         * case is called with isInstall TRUE
         */

        /**
         * Check input parameters validity
         */
        SubjectAlternativeNameType mySubjectAltName = subjectAltName;
        this.issueCertFromXMLCheckInput(entityName, distinguishName, entityProfileName, ksInfoList, tsInfoList, crlInfoList);

        LOG.info("issueCertificate END ENTITY=" + entityName);

        /**
         * Get remote object
         */
        final CredMServiceWrapper serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL,
                true);

        /**
         * Get Entity to check whether it exists or not
         */
        CredentialManagerEntity cmEntity = null;
        String localEntityProfileName = null;
        try {
            if ((cmEntity = serviceWrapper.getExistingEntity(entityName)) != null) {
                // Entity Found: get profileName from entity

                localEntityProfileName = cmEntity.getEntityProfileName();
                LOG.info("Entity Found: get profileName from entity " + localEntityProfileName);
            } else {
                LOG.info("Error while getting existing Entity");
                throw (new IssueCertificateException("Error while getting existing Entity"));
            }
        } catch (final CredentialManagerEntityNotFoundException e) {
            // Entity Not Found: get profileName from XML
            localEntityProfileName = entityProfileName;
            LOG.info("Entity Not Found: get profileName from XML " + localEntityProfileName + "; Proceeding to create a new one");
        }

        /**
         * Get Profile params: endEntityProfileName
         */
        final CredentialManagerProfileInfo profileInfo = serviceWrapper.getProfile(localEntityProfileName);
        if (profileInfo == null) {
            serviceWrapper.printErrorOnSystemRecorder("Profile get FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                    localEntityProfileName, null);
            throw (new IssueCertificateException("ProfileInfo is NULL"));
        }
        LOG.debug("keyPairSize = " + profileInfo.getKeyPairAlgorithm().getKeySize().toString() + " keyPairAlgorithm = "
                + profileInfo.getKeyPairAlgorithm().getName());

        /**
         * Logic to set CredentialManagerSubjectAltName cmSubjectAltName from XML or Profile
         */
        final SANConvertHandler convertHandler = new SANConvertHandler();

        // if there is no data inside the subjectAltName, we need to nullify the
        // whole object
        if (convertHandler.isSubjectAltNameEmpty(mySubjectAltName)) {
            mySubjectAltName = null;
        }

        /**
         * Get and Create Entity params: entityName, subjectAltName, OTP, endEntityProfileName
         */
        final CredentialManagerSubjectAltName cmSubjectAltName = convertHandler.setSubjectAltName(mySubjectAltName, profileInfo);
        final CredentialManagerSubject cmSubject = profileInfo.getSubjectByProfile().updateFromSubjectDN(distinguishName);
        CredentialManagerEntity entity = null;
        try {
            entity = serviceWrapper.createAndGetEntity(entityName, cmSubject, cmSubjectAltName, profileInfo.getKeyPairAlgorithm(),
                    localEntityProfileName);
            if (entity == null) {
                serviceWrapper.printErrorOnSystemRecorder("Entity create FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api", entityName,
                        "entity null");
                throw (new IssueCertificateException("Entity is NULL"));
            }
        } catch (final IssueCertificateException e) {
            serviceWrapper.printErrorOnSystemRecorder("Entity create FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api", entityName,
                    "exception");
            throw (new IssueCertificateException(e.getMessage()));
        }

        /**
         * check certificate validity
         */
        final CertificateManager certificateManager = new CertificateManager(serviceWrapper);
        boolean certValid = true;
        boolean workDone = false;

        final CredentialManagerPIBParameters parameters = serviceWrapper.getPibParameters();

        // here we can force the failure of the test and then the renewal of all the certificates
        // only if the credentialmanagercli is runing with -i option
        if (isInstall) {
            certValid = this.updateCertValid();
        }

        if (certValid == true) {
            for (final KeystoreInfo ksInfo : ksInfoList) {
                try {
                    certValid = certValid
                            && certificateManager.checkCertificateValidity(ksInfo, cmSubject.retrieveSubjectDN(), entity, firstDailyRun, parameters);
                } catch (final CertificateValidationException e) {
                    serviceWrapper.printErrorOnSystemRecorder("Certificate check FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                            entityName, "exception");
                    throw (new IssueCertificateException("checkCertificateValidation : " + e.getMessage()));
                }
            }
        }

        // certValid false means at least one keystore has been detected has
        // wrong or invalid
        if (!certValid) {

            try {
                /**
                 * delete old keystore
                 */
                certificateManager.clearKeystores(ksInfoList);
                /**
                 * Create Key Pair Create CSR Get Certificate
                 */
                LOG.info("Regenerate CERTIFICATE for " + entityName);
                serviceWrapper.printCommandOnSystemRecorder("Regenerating Certificate", CommandPhase.STARTED, "credential-manager-service-api",
                        entityName, null);
                System.out.println("Regenerate CERTIFICATE for " + entityName);
                certificateManager.generateKey(profileInfo);
                certificateManager.generateCSR(entity, profileInfo, certificateExtensionInfo);
                // certificateManager.generateCertificate(cmSubject.retrieveSubjectDN(),
                // profileInfo);
                certificateManager.generateCertificate(entityName, profileInfo, certificateChain, null);

                /**
                 * write Key and Certificate
                 */
                certificateManager.writeKeyAndCertificate(ksInfoList);
            } catch (IssueCertificateException | OtpExpiredException | OtpNotValidException e) {
                serviceWrapper.printErrorOnSystemRecorder("Certificate write FAILURE", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entityName, "exception");
                throw (new IssueCertificateException(e.getMessage()));
            }

            serviceWrapper.printCommandOnSystemRecorder("Certificate write SUCCESS", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api", entityName, null);

            if (certificateManager.getRevokeCertId() != null) {
                // there is a certificate to revoke
                LOG.info("Revoke OLD CERTIFICATE for " + entityName);
                System.out.println("Revoke OLD CERTIFICATE for " + entityName);

                // result of operation could be check using result =
                if (certificateManager.revokeCertificate()) {
                    // success
                    serviceWrapper.printCommandOnSystemRecorder("Certificate revoke SUCCESS", CommandPhase.FINISHED_WITH_SUCCESS,
                            "credential-manager-service-api", entityName, null);
                } else {
                    // failure
                    serviceWrapper.printCommandOnSystemRecorder("Certificate revoke FAILURE", CommandPhase.FINISHED_WITH_ERROR,
                            "credential-manager-service-api", entityName, null);
                }
            }
            // work has been done
            workDone = true;
        } else {
            System.out.println("Certificate is valid: nothing to be done for " + entityName);
        }

        /**
         * this part is executed only in the install phase (the check phase will call a specific "checkTrust" method
         */

        if (isInstall) {

            // install phase always requires TRUE as result
            workDone = true;

            final TrustManager trustManager = new TrustManager(serviceWrapper);
            final CrlManager crlManager = new CrlManager(serviceWrapper);
            try {
                /**
                 * wipe out Trust data
                 */
                trustManager.clearTruststores(tsInfoList);
                /**
                 * get and write Trust
                 */
                trustManager.retrieveTrust(entity.getEntityProfileName());
                trustManager.writeTrust(tsInfoList);
            } catch (final IssueCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("Trust write FAILURE (Install)", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entity.getEntityProfileName(), null);
                throw (new IssueCertificateException(e.getMessage()));
            }
            serviceWrapper.printCommandOnSystemRecorder("Trust write SUCCESS (Install)", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api", entity.getEntityProfileName(), null);

            try {
                /**
                 * delete CRL
                 */
                crlManager.clearCrlStore(crlInfoList);
                /**
                 * get and write CRL
                 */
                crlManager.retrieveCrlList(entity.getEntityProfileName());

                crlManager.writeCrlList(crlInfoList);
            } catch (final IssueCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("CRL write FAILURE (Install)", ErrorSeverity.ERROR, "credential-manager-service-api",
                        entity.getEntityProfileName(), null);
                throw (new IssueCertificateException(e.getMessage()));
            }
            serviceWrapper.printCommandOnSystemRecorder("CRL write SUCCESS (Install)", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api", entity.getEntityProfileName(), null);

        }
        return workDone;

    } // end of issueCertificateAndTrust

    /**
     * updateCertValid
     *
     * @return certValid
     * @throws IssueCertificateException
     */
    private boolean updateCertValid() throws IssueCertificateException {

        Properties jarProp = null;
        String optionsLocation = null;
        File inputfile = null;
        Properties extProp = null;

        InputStream input = IfCertificateManagementImpl.class.getClassLoader().getResourceAsStream("config.properties");

        jarProp = new Properties();
        // it is expected the file is in the jar
        try {
            jarProp.load(input);
        } catch (final IOException e) {
            throw new IssueCertificateException(e.getMessage());
        }

        optionsLocation = jarProp.getProperty(this.GLOBAL_CREDMA_OPTION_FILE);

        if (optionsLocation != null) {

            // it is expected the file has a full path
            inputfile = new File(optionsLocation);
            try {
                input = new FileInputStream(inputfile);
            } catch (final FileNotFoundException e) {
                // File not found
                System.out.println("CONFIGURATION READ: credentialManagerConfigurator file not found");
                LOG.info("CONFIGURATION READ: credentialManagerConfigurator file not found");
                return true;
            }

            extProp = new Properties();

            try {
                extProp.load(input);
            } catch (final IOException e) {
                // File not accessible
                System.out.println("CONFIGURATION READ: credentialManagerConfigurator file not accessible");
                LOG.info("CONFIGURATION READ: credentialManagerConfigurator file not accessible");
                return true;
            }

            final String forceCertString = extProp.getProperty(this.FORCE_RENEWAL);
            if (forceCertString != null) {
                if (forceCertString.toLowerCase().equals("true")) {
                    System.out.println("CONFIGURATION READ: Force RENEWAL CERTIFICATES");
                    LOG.info("CONFIGURATION READ: Force RENEWAL CERTIFICATES");
                    return (false); // to make the check fail, in order to force a renewal
                }
            } else {
                System.out.println("CONFIGURATION READ: Force RENEWAL setting not found");
                LOG.info("CONFIGURATION READ: Force RENEWAL setting not found");
            }
        }

        return true;
    } // end of updateCertValid

    //
    // UTILITY
    //

    /**
     * @param entityName
     * @param entityProfileName
     * @param ksInfoList
     * @param tsInfoList
     * @throws IssueCertificateException
     */
    private void issueCertFromXMLCheckInput(final String entityName, final String distinguishName, final String entityProfileName,
                                            final List<KeystoreInfo> ksInfoList, final List<TrustStoreInfo> tsInfoList,
                                            final List<TrustStoreInfo> crlInfoList)
            throws IssueCertificateException {
        /**
         * Check input parameters
         */
        if (entityName == null || entityName.isEmpty()) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_XMLENTITYNAME, entityName);
            throw (new IssueCertificateException("entityName is NULL or empty"));
        }

        if (distinguishName != null) {
            /**
             * Check LDAP format (distinguishName not null)
             */
            try {
                @SuppressWarnings("unused")
                final LdapName xmlLdapName = new LdapName(distinguishName);
            } catch (final InvalidNameException e) {
                throw (new IssueCertificateException("distinguishName is not LDAP"));
            }
        }

        if (entityProfileName == null || entityProfileName.isEmpty()) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_XMLPROFILENAME, entityName);
            throw (new IssueCertificateException("entityProfileName is NULL or empty"));
        }

        if (ksInfoList == null || ksInfoList.isEmpty()) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_XMLKSLIST, entityName);
            throw (new IssueCertificateException("ksInfoList is NULL or empty"));
        }

        for (final KeystoreInfo ks : ksInfoList) {
            if (!ks.isValid()) {
                LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_XMLKSENTRY, entityName);
                throw (new IssueCertificateException("ksInfo not valid or wrong folder"));
            }
        }

        /**
         * Note that tsInfoList can be null or empty
         */
        if (tsInfoList != null && !tsInfoList.isEmpty()) {
            for (final TrustStoreInfo ts : tsInfoList) {
                if (!ts.isValid()) {
                    LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_XMLTSENTRY, entityName);
                    throw (new IssueCertificateException("tsInfo not valid or wrong folder"));
                }
            }
        }

        /**
         * Note that crlInfoList can be null or empty
         */
        if (crlInfoList != null && !crlInfoList.isEmpty()) {
            for (final TrustStoreInfo cs : crlInfoList) {
                if (!cs.isValid()) {
                    LOG.error(ErrorMsg.API_ERROR_BUSINESS_XMLCRLENTRY, entityName);
                    throw (new IssueCertificateException("crlInfo not valid or wrong folder"));
                }
            }
        }
    } // end of issueCertFromXMLCheckInput

    /**
     * @param entityInfo
     * @param ksInfo
     * @throws InvalidCertificateFormatException
     */
    private void issueCertFromEnisCheckInput(final EntityInfo entityInfo, final KeystoreInfo ksInfo)
            throws IssueCertificateException, InvalidCertificateFormatException {

        if (entityInfo == null || !entityInfo.isValid()) {
            if (entityInfo != null) {
                LOG.error(ErrorMsg.API_ERROR_BUSINESS_ENISENTITY, entityInfo.getEntityName());
            }
            throw (new IssueCertificateException("entityInfo is NULL or its fields empty"));
        }

        // For ENIS/SLS/AMOS operator we only accept one single file for both key and cert (and parent dir is writable)
        if (ksInfo == null || !ksInfo.isKeyAndCertLocationValid() || !ksInfo.isKeyAndCertLocationAccessible()) {
            if (ksInfo != null) {
                LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_ENISKSENTRY, ksInfo.getAlias(), entityInfo.getEntityName());
            }
            throw (new IssueCertificateException("ksInfo is NULL or empty or not accessible"));
        }

        // For ENIS/SLS/AMOS operators we can accept PKCS12 or XML
        if ((ksInfo.getCertFormat() != CertificateFormat.PKCS12) && (ksInfo.getCertFormat() != CertificateFormat.LEGACY_XML)) {
            LOG.error("Invalid certificate format, it must be PKCS12 or LEGACY_XML");
            throw new InvalidCertificateFormatException("Invalid certificate format, it must be PKCS12 or LEGACY_XML");
        }

        if (ksInfo.getCertFormat() == CertificateFormat.PKCS12) {
            if (ksInfo.getAlias() == null || ksInfo.getAlias().isEmpty()) {
                LOG.error("Alias must be not null or empty for PKCS12");
                throw (new IssueCertificateException("Alias is NULL or empty"));
            }

        }
    } // end of issueCertFromEnisCheckInput

    /**
     * @param cMsubject
     * @return
     */
    private Subject buildSubject(final CredentialManagerSubject cMsubject) {

        final Subject subject = new Subject();

        subject.setCommonName(cMsubject.getCommonName());
        subject.setSurName(cMsubject.getSurName());
        subject.setCountryName(cMsubject.getCountryName());
        subject.setLocalityName(cMsubject.getLocalityName());
        subject.setStateOrProvinceName(cMsubject.getStateOrProvinceName());
        subject.setStreetAddress(cMsubject.getStreetAddress());
        subject.setOrganizationalUnitName(cMsubject.getOrganizationalUnitName());
        subject.setOrganizationName(cMsubject.getOrganizationName());
        subject.setDnQualifier(cMsubject.getDnQualifier());
        subject.setTitle(cMsubject.getTitle());
        subject.setGivenName(cMsubject.getGivenName());
        subject.setSerialNumber(cMsubject.getSerialNumber());

        return subject;
    }

    /**
     * @param entityName
     * @param entityType
     * @param certificateStatus
     *
     * @return List<CertificateSummary>
     *
     * @throws CertificateNotFoundException
     * @throws GetCertificatesByEntityNameException
     * @throws EntityNotFoundException
     *
     */
    @Override
    public List<CertificateSummary> getCertificatesByEntityName(final String entityName, final EntityType entityType,
                                                                final CertificateStatus... certificateStatus)
            throws CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException {

        CredMServiceWrapper serviceWrapper;
        try {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, true);
        } catch (final IssueCertificateException e) {
            throw new GetCertificatesByEntityNameException(e);
        }

        //CertificateStatus conversion
        final CredentialManagerCertificateStatus[] credManCertStatusArray = new CredentialManagerCertificateStatus[certificateStatus.length];
        for (int i = 0; i < credManCertStatusArray.length; i++) {
            credManCertStatusArray[i] = CredentialManagerCertificateStatus.fromValue(certificateStatus[i].value().toUpperCase());

            /*
             * DEBUG
             */
            LOG.debug("getCertificatesByEntityName; coversion from CertificateStatus to CredentialManagerCertificateStatus : value = "
                    + credManCertStatusArray[i].value());
        }

        //entityType conversion
        final CredentialManagerEntityType credMEntityType = CredentialManagerEntityType.fromString(entityType.getValue());

        /*
         * DEBUG
         */
        LOG.debug("getCertificatesByEntityName; conversion from  EntityType to CredentialManagerEntityType : value = " + credMEntityType.toString());

        List<CredentialManagerX500CertificateSummary> credManCertsSummaryList = null;
        credManCertsSummaryList = serviceWrapper.getCertificatesByEntityName(entityName, credMEntityType, credManCertStatusArray);

        final List<CertificateSummary> certSummaryList = new ArrayList<CertificateSummary>();
        for (final CredentialManagerX500CertificateSummary credManX500CertSummary : credManCertsSummaryList) {
            final String issuerDN = credManX500CertSummary.getIssuerX500Principal().getName();
            final String subjectDN = credManX500CertSummary.getSubjectX500Principal().getName();
            final String certificateSN = credManX500CertSummary.getCertificateSN().toString();
            final CertificateStatus certStatus = CertificateStatus.fromValue(credManX500CertSummary.getCertificateStatus().value().toUpperCase());

            /*
             * DEBUG
             */
            LOG.debug("getCertificatesByEntityName; retrieved from CredM Service : issuerDN = " + issuerDN + "; subjectDN = " + subjectDN
                    + "; certificateSN = " + certificateSN + "; cert Status = " + certStatus.value());

            final CertificateSummary certSum = new CertificateSummary(issuerDN, subjectDN, certificateSN, certStatus);
            certSummaryList.add(certSum);
        }

        return certSummaryList;
    }

    /**
     *
     * @param issuerDN
     *            : string representation of an X.500 distinguished name for issuer
     * @param subjectDn
     *            : string representation of an X.500 distinguished name for subject
     * @param serialNumber
     *            : certificate serial number in string format
     * @param revocationReason
     *
     * @return Boolean
     *
     * @throws CertificateNotFoundException
     * @throws ExpiredCertificateException
     * @throws AlreadyRevokedCertificateException
     * @throws RevokeEntityCertificateException
     *
     */
    @Override
    public Boolean revokeEntityCertificate(final String issuerDN, final String subjectDN, final String certificateSN,
                                           final CrlReason revocationReason)
            throws CertificateNotFoundException, ExpiredCertificateException, AlreadyRevokedCertificateException, RevokeEntityCertificateException {

        if (issuerDN == null || issuerDN.isEmpty()) {
            LOG.error("issuerDN not valid: it is null or empty");
            throw (new RevokeEntityCertificateException("issuerDN not valid: it is null or empty"));
        }

        if (subjectDN == null || subjectDN.isEmpty()) {
            LOG.error("subjectDN not valid: it is null or empty");
            throw (new RevokeEntityCertificateException("subjectDN not valid: it is null or empty"));
        }

        if (certificateSN == null || certificateSN.isEmpty()) {
            LOG.error("certificateSN not valid: it is null or empty");
            throw (new RevokeEntityCertificateException("certificateSN not valid: it is null or empty"));
        }

        if (revocationReason == null) {
            LOG.error("RevocationReason not valid: it cannot be null");
            throw (new RevokeEntityCertificateException("RevocationReason not valid: it cannot be null"));
        }

        /**
         * Get remote object
         */
        CredMServiceWrapper serviceWrapper;
        try {
            serviceWrapper = this.credMServiceWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, true);
        } catch (final IssueCertificateException e) {
            LOG.error("revokeCertificate ERROR: buildServiceWrapper failed");
            throw (new RevokeEntityCertificateException("revokeEntityCertificate: buildServiceWrapper failed"));
        }

        // Retrieve certificate identifier to be subsequently revoked
        final CredentialManagerCertificateIdentifier certificateIdentifer = CertificateUtils.buildIdentifierFromStrings(issuerDN, subjectDN,
                certificateSN);

        // Revoke certificate
        if (certificateIdentifer != null) {
            try {
                serviceWrapper.revokeCertificateById(certificateIdentifer, CredentialManagerRevocationUtils.convertRevocationReason(revocationReason),
                        Calendar.getInstance().getTime());
            } catch (final CredentialManagerInternalServiceException e) {
                serviceWrapper.printErrorOnSystemRecorder("revokeEntityCertificate FAILURE", ErrorSeverity.ERROR,
                        "credential-manager-service-api: Subject DN = ", subjectDN, "revoke error");
                throw new RevokeEntityCertificateException(e.getMessage());
            } catch (final CredentialManagerCertificateNotFoundException e) {
                serviceWrapper.printErrorOnSystemRecorder("revokeEntityCertificate FAILURE", ErrorSeverity.ERROR,
                        "credential-manager-service-api: Subject DN", subjectDN, "certificate Not Found");
                throw new CertificateNotFoundException(e.getMessage());
            } catch (final CredentialManagerExpiredCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("revokeEntityCertificate FAILURE", ErrorSeverity.ERROR,
                        "credential-manager-service-api: Subject DN", subjectDN, "certificate is expired");
                throw new ExpiredCertificateException(e.getMessage());
            } catch (final CredentialManagerAlreadyRevokedCertificateException e) {
                serviceWrapper.printErrorOnSystemRecorder("revokeEntityCertificate FAILURE", ErrorSeverity.ERROR,
                        "credential-manager-service-api: Subject DN", subjectDN, "certificate is already revoked");
                throw new AlreadyRevokedCertificateException(e.getMessage());
            }

            serviceWrapper.printCommandOnSystemRecorder("revokeEntityCertificate", CommandPhase.FINISHED_WITH_SUCCESS,
                    "credential-manager-service-api: Subject DN", subjectDN, null);

        } else {
            LOG.error("revokeEntityCertificate ERROR: failed, wrong input parameters format.");
            throw (new RevokeEntityCertificateException("revokeEntityCertificate: failed, wrong input parameters format."));
        }

        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement#reIssueLegacyXMLCertificate(com.ericsson.oss.itpf.security.credmsapi.api.
     * model.EntityInfo, java.lang.String, java.lang.Boolean, java.lang.String, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean reIssueLegacyXMLCertificate(final EntityInfo entityInfo, final String certificateLocation, final Boolean certificateChain,
                                               final String passwordLocation, final CrlReason revocationReason)
            throws ReIssueLegacyXMLCertificateException, EntityNotFoundException, OtpNotValidException, OtpExpiredException {

        if (certificateChain == null) {
            LOG.error("reIssueLegacyXMLCertificate ERROR: invalid chain parameter");
            throw (new ReIssueLegacyXMLCertificateException("reIssueLegacyXMLCertificate: invalid chain parameter"));
        }

        BufferedReader bufferedReader = null;

        // Check specific input parameters
        if (passwordLocation == null || passwordLocation.isEmpty()) {
            LOG.info("reIssueLegacyXMLCertificate INFO: Password from LOCAL file");

            final InputStream is = IfCertificateManagementImpl.class.getClassLoader().getResourceAsStream("keyEncrPwdFile.txt");
            bufferedReader = new BufferedReader(new InputStreamReader(is));
        } else {
            LOG.info("reIssueLegacyXMLCertificate INFO: Password from INPUT file");
            try {
                bufferedReader = new BufferedReader(new FileReader(passwordLocation));
            } catch (final FileNotFoundException e) {
                LOG.error("reIssueLegacyXMLCertificate ERROR: input file NOT FOUND");
                throw (new ReIssueLegacyXMLCertificateException("reIssueLegacyXMLCertificate: Password file not found"));
            }

        }

        // Extract password from file
        String password = null;
        try {
            password = bufferedReader.readLine();
            bufferedReader.close();
        } catch (final IOException e) {
            LOG.error("reIssueLegacyXMLCertificate ERROR: Password file not found or readable");
            throw (new ReIssueLegacyXMLCertificateException("reIssueLegacyXMLCertificate: Password file not found or readable"));
        }

        // Build KsInfo
        final KeystoreInfo ksInfo = new KeystoreInfo(certificateLocation, null, null, null, CertificateFormat.LEGACY_XML, password, null);

        try {
            this.innerReissueCertificate(entityInfo, ksInfo, revocationReason, certificateChain.booleanValue());
        } catch (InvalidCertificateFormatException | ReissueCertificateException e) {
            LOG.error("reIssueLegacyXMLCertificate ERROR: Reissue Certificate failed");
            throw (new ReIssueLegacyXMLCertificateException("reIssueLegacyXMLCertificate: " + e.getMessage()));
        }

        return true;

    }
} // end of IfCertificateManagementImpl
