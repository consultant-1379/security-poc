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
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.ejb.LocalBean;
import javax.ejb.Stateless;
import javax.inject.Inject;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.ProfileManager;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.util.CertificateUtils;
import com.ericsson.oss.itpf.security.credmservice.util.CredMJKSWriter;
import com.ericsson.oss.itpf.security.credmservice.util.FileUtils;
import com.ericsson.oss.itpf.security.credmservice.util.JKSReader;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmservice.util.StorageFilesInformation;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.itpf.security.keymanagement.exception.KeyGeneratorException;

@LocalBean
@Stateless
public class CredMServiceSelfCredentialsManager {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceSelfCredentialsManager.class);

    private static final String PROFILE_NAME = "credMServiceProfile";
    static final String JBOSS_EJB_KEY_ALIAS_DEFAULT = "credmservice";

    private static final String JBOSS_EJB_KEY_ALIAS_NAME = "jbossEjbCertificateAliasName";
    private static final String JBOSS_EJB_STORE_PASS_WD_NAME = "jbossEjbKeyStorePassword";

    @EServiceRef
    private CredMService credMService;

    @Inject
    private ProfileManager profileManager;

    @Inject
    private SystemRecorderWrapper systemRecorder;

    private CredentialManagerProfileInfo profile = null;
    private CredentialManagerEntity eentity = null;
    private CredentialManagerX509Certificate[] certificate = null;
    private Map<String, CredentialManagerCertificateAuthority> intCa = null;
    private Map<String, CredentialManagerCertificateAuthority> extCa = null;
    private KeyPair keyPair = null;
    private final String className = this.getClass().getSimpleName();

    public void generateJBossCredentials() throws CredentialManagerStartupException {
        log.info("trying to create certificates");
        try {
            this.getProfile();
            this.createEndEntity();
            this.getCertificate();
            this.getTrust();
            this.saveKeyStores();
        } catch (final CredentialManagerStartupException e) {
            throw e;
        } catch (final Exception e) {
            throw new CredentialManagerStartupException("Unrecognised exception during CredMService startup procedure", e.getCause());
        }
    }

    /**
     * @throws CredentialManagerStartupException
     * 
     */
    private void getProfile() throws CredentialManagerStartupException {
        log.info("Getting Profile");
        try {
            this.profile = this.getProfile(PROFILE_NAME);
        } catch (CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException | CredentialManagerProfileNotFoundException | CredentialManagerInvalidProfileException e) {
            throw new CredentialManagerStartupException(e.getMessage());
        }

        if (this.profile == null) {
            throw new CredentialManagerStartupException("Error getting end entity profile name : " + PROFILE_NAME);
        }
    }

    public CredentialManagerProfileInfo getProfile(final String endEntityProfileName) throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {

        CredentialManagerProfileInfo profileInfo = null;
        profileInfo = this.profileManager.getProfile(endEntityProfileName);

        return profileInfo;
    }

    /**
     * @throws CredentialManagerStartupException
     * 
     */
    private void createEndEntity() throws CredentialManagerStartupException {
        log.info("Creating End Entity");

        String hostname;
        try {
            hostname = InetAddress.getLocalHost().getHostName();
            final CredentialManagerSubject subject = this.profile.getSubjectByProfile();
            subject.setCommonName(hostname);

            final CredentialManagerSubjectAltName subjectAltName = this.profile.getSubjectDefaultAlternativeName();
            final CredentialManagerAlgorithm keyGenerationAlgorithm = this.profile.getKeyPairAlgorithm();

            try {
                this.eentity = this.credMService.createAndGetEntity(this.getEntitynameByHostname(hostname), subject, subjectAltName,
                        keyGenerationAlgorithm, PROFILE_NAME);
            } catch (final CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException
                    | CredentialManagerInvalidEntityException | CredentialManagerProfileNotFoundException e) {
                throw new CredentialManagerStartupException(e.getMessage());
            }
            if (this.eentity == null) {
                throw new CredentialManagerStartupException("Error getting end entity for " + hostname);
            }
        } catch (final UnknownHostException e) {
            throw new CredentialManagerStartupException("Error getting end entity profile name : " + PROFILE_NAME, e.getCause());
        }
    }

    /**
     * @throws CredentialManagerStartupException
     * 
     */
    private void getCertificate() throws CredentialManagerStartupException {
        log.info("getting Certificate");
        try {
            this.keyPair = this.generateKeyPair(); // TODO DespicableUs catch runtime
            // exception
        } catch (final KeyGeneratorException e) {
            throw new CredentialManagerStartupException("Error generating the keyPair.", e.getCause());
        }

        final CredentialManagerPKCS10CertRequest csr = this.createCSR(this.keyPair);

        try {
            // inserted chain in the CredMService certificate in order to manage reissue of certificates with reKey 
            this.certificate = this.credMService.getCertificate(csr, this.eentity.getName(), true, null);
        } catch (CredentialManagerCertificateEncodingException | CredentialManagerEntityNotFoundException | CredentialManagerCertificateGenerationException | CredentialManagerInvalidCSRException
                | CredentialManagerInvalidEntityException | CredentialManagerCertificateExsitsException e) {
            throw new CredentialManagerStartupException(e.getMessage());
        }
    }

    /**
     * @return
     * @throws IssueCertificateException
     */
    private KeyPair generateKeyPair() {
        /**
         * Create Key Pair
         */
        return KeyGenerator.getKeyPair(this.profile.getKeyPairAlgorithm().getName(), this.profile.getKeyPairAlgorithm().getKeySize());
    }

    /**
     * @return
     * @throws CredentialManagerStartupException
     */
    private CredentialManagerPKCS10CertRequest createCSR(final KeyPair keyPair) throws CredentialManagerStartupException {
        CredentialManagerPKCS10CertRequest ret = null;

        try {
            ret = new CredentialManagerPKCS10CertRequest(CertificateUtils.generatePKCS10Request(this.profile.getSignatureAlgorithm().getName(),
                    this.eentity, keyPair, null, BouncyCastleProvider.PROVIDER_NAME));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | IOException e) {
            throw new CredentialManagerStartupException("Error creating CSR.", e.getCause());
        }
        return ret;
    }

    /**
     * @throws CredentialManagerStartupException
     * 
     */
    private void getTrust() throws CredentialManagerStartupException {

        CredentialManagerTrustMaps caMaps = new CredentialManagerTrustMaps();

        try {
            caMaps = this.credMService.getTrustCertificates(PROFILE_NAME);
        } catch (CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException | CredentialManagerProfileNotFoundException | CredentialManagerCertificateEncodingException
                | CredentialManagerInvalidProfileException e) {
            throw new CredentialManagerStartupException("Error getting trust certificate.", e.getCause());
        }
        this.intCa = caMaps.getInternalCATrustMap();
        this.extCa = caMaps.getExternalCATrustMap();
    }

    /**
     * @throws CredentialManagerStartupException
     * 
     */
    private void saveKeyStores() throws CredentialManagerStartupException {

        final CredMJKSWriter keystore = new CredMJKSWriter(StorageFilesInformation.getKeystoreFilePath(), getKeystoresPassword());
        // inserted chain in the CredMService certificate in order to manage reissue of certificates with reKey 
        final Certificate cert = this.certificate[0].retrieveCertificate();
        int certCounter = 0;
        Certificate[] chain = new Certificate[this.certificate.length];

        for (CredentialManagerX509Certificate X509Cert : this.certificate) {
            chain[certCounter] = X509Cert.retrieveCertificate();
            certCounter++;
        }

        keystore.storeKeyPair(this.keyPair.getPrivate(), cert, getKeystoreAliasName(), chain);

        final CredMJKSWriter truststore = new CredMJKSWriter(StorageFilesInformation.getTruststoreFilePath(), getKeystoresPassword());
        truststore.addTrustedEntries(this.intCa, this.extCa, getKeystoreAliasName());
    }

    /**
     * It checks the validity period of the given certificate
     * 
     * @param certificate
     * @return
     * @throws CredentialManagerStartupException
     */
    private static boolean checkValidityDate(final Certificate certificate) throws CredentialManagerStartupException {
        boolean ret = false;
        X509Certificate x509Certificate = null;
        final JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();

        try {
            x509Certificate = jcaConverter.getCertificate(new X509CertificateHolder(certificate.getEncoded()));
            try {
                x509Certificate.checkValidity();
                ret = true; // certificate is valid!
            } catch (final CertificateExpiredException e) {
                log.error("CredMService EJB certificate expired!!");
            } catch (final CertificateNotYetValidException e) {
                log.error("CredMService EJB certificate not yet valid!!");
            }
        } catch (CertificateException | IOException e) {
            log.error("Cannot convert CredMService EJB certificate. Corrupted?");
            throw new CredentialManagerStartupException("Cannot convert CredMService EJB certificate. Corrupted?", e.getCause());
        }
        return ret;
    }

    /**
     * Retrieves from property file, the password of the keystore containing the certificate related to jboss
     * 
     * @return password of the keystore containing the jboss certificate
     */
    public static String getKeystoresPassword() throws CredentialManagerStartupException {
        final String aliasTrustName = PropertiesReader.getProperties(StorageFilesInformation.FILE_PROPERTIES)
                .getProperty(JBOSS_EJB_STORE_PASS_WD_NAME);
        if (aliasTrustName != null) {
            return aliasTrustName;
        } else {
            throw new CredentialManagerStartupException("keystore password is missing in config.properties file.");
        }
    }

    /**
     * Perform a validity check of the certificate based on alias name and on the validity period
     * 
     * @return true if the certificate is valid
     */
    static boolean checkCertificateValidity() {
        boolean ret = false;
        try {
            log.info("checking keystore : " + StorageFilesInformation.getKeystoreFilePath());
            final JKSReader jksReader = new JKSReader(StorageFilesInformation.getKeystoreFilePath(), getKeystoresPassword(), "JKS");
            if (jksReader.isAliasPresent(getKeystoreAliasName())) {
                ret = checkValidityDate(jksReader.getCertificate(getKeystoreAliasName()));
            }
        } catch (final CredentialManagerStartupException e) {
            log.error("Unexpected error checking certificate validity. Returns not valid");
            e.printStackTrace();
        }
        return ret;
    }

    /**
     * Perform a check of the truststore
     * 
     * @return true if the certificate is valid
     */
    public boolean checkTrustValidity() {
        final boolean ret = false;
        log.info("checking truststore : " + StorageFilesInformation.getTruststoreFilePath());

        return FileUtils.isExist(StorageFilesInformation.getTruststoreFilePath());
    }

    /**
     * Retrieves the alias of the keystore certificate related to jboss, read from property
     * 
     * @return alias referred to the jboss certificate in the keystore
     */
    public static String getKeystoreAliasName() {
        final String aliasKeyName = PropertiesReader.getProperties(StorageFilesInformation.FILE_PROPERTIES).getProperty(JBOSS_EJB_KEY_ALIAS_NAME);
        if (aliasKeyName != null) {
            return aliasKeyName;
        } else {
            return JBOSS_EJB_KEY_ALIAS_DEFAULT;
        }
    }

    /**
     * @return
     * @throws CredentialManagerStartupException
     */
    public boolean checkJbossEntityReissueState() {
        boolean ret = false;
        String hostname;
        try {
            hostname = InetAddress.getLocalHost().getHostName();

            try {
                this.eentity = this.credMService.getEntity(this.getEntitynameByHostname(hostname));
            } catch (final CredentialManagerEntityNotFoundException e) {
                this.systemRecorder.recordError("CredentialManagerEntityNotFoundException", ErrorSeverity.ERROR, className, "checkJbossEntityReissueState [" + this.getEntitynameByHostname(hostname)
                        + "]", e.getMessage());
                return true;
            } catch (final CredentialManagerInternalServiceException e) {
                this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, className, "checkJbossEntityReissueState [" + this.getEntitynameByHostname(hostname)
                        + "]", e.getMessage());
                return true;
            } catch (final CredentialManagerInvalidEntityException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, className, "checkJbossEntityReissueState [" + this.getEntitynameByHostname(hostname)
                        + "]", e.getMessage());
                return true;
            } catch (final CredentialManagerInvalidArgumentException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidArgumentException", ErrorSeverity.ERROR, className, "checkJbossEntityReissueState [" + this.getEntitynameByHostname(hostname)
                        + "]", e.getMessage());
                return true;
            }

            if (this.eentity == null) {
                this.systemRecorder.recordError("Entity Null", ErrorSeverity.ERROR, className, "Entity Null", "");
                return true;
            }
            if (this.eentity.getEntityStatus() != CredentialManagerEntityStatus.REISSUE) {
                ret = true;
            }
        } catch (final UnknownHostException e) {
            this.systemRecorder.recordError("UnknownHostException", ErrorSeverity.ERROR, className, "checkJbossEntityReissueState: Error getting hostname : InetAddress.getLocalHost().getHostName()",
                    e.getMessage());
            return true;
        }
        return ret;
    }

    /**
     * @return
     * @throws CredentialManagerStartupException
     */
    public boolean checkTrusts() {

        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = readTrustsFromKeystore();
        try {
            final CredentialManagerTrustMaps result = this.credMService.compareTrustAndRetrieve(PROFILE_NAME, currentTrustIdentifiers, true, true);
            if (result == null) {
                // check is ok, return null to show there is null to update
                return true;
            }
        } catch (final CredentialManagerProfileNotFoundException e) {
            this.systemRecorder.recordError("CredentialManagerProfileNotFoundException", ErrorSeverity.ERROR, className,
                    "checkTrusts [" + PROFILE_NAME + "]", e.getMessage());
            return true;
        } catch (final CredentialManagerInternalServiceException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, className,
                    "checkTrusts [" + PROFILE_NAME + "]", e.getMessage());
            return true;
        } catch (final CredentialManagerCertificateEncodingException e) {
            this.systemRecorder.recordError("CredentialManagerCertificateEncodingException", ErrorSeverity.ERROR, className,
                    "checkTrusts [" + PROFILE_NAME + "]", e.getMessage());
            return true;
        } catch (final CredentialManagerInvalidArgumentException e) {
            this.systemRecorder.recordError("CredentialManagerInvalidArgumentException", ErrorSeverity.ERROR, className,
                    "checkTrusts [" + PROFILE_NAME + "]", e.getMessage());
            return true;
        } catch (final CredentialManagerInvalidProfileException e) {
            this.systemRecorder.recordError("CredentialManagerInvalidProfileException", ErrorSeverity.ERROR, className,
                    "checkTrusts [" + PROFILE_NAME + "]", e.getMessage());
            return true;
        }

        return false;
    }

    /**
     * 
     * The method retrieves the certificate from TrustStore
     * 
     * @return
     */
    public static SortedSet<CredentialManagerCertificateIdentifier> readTrustsFromKeystore() {
        final SortedSet<CredentialManagerCertificateIdentifier> trustStoreIdentifiers = new TreeSet<CredentialManagerCertificateIdentifier>();

        try {
            final JKSReader jksReader = new JKSReader(StorageFilesInformation.getTruststoreFilePath(), getKeystoresPassword(), "JKS");
            final List<Certificate> certs = jksReader.getAllCertificates();
            for (final Certificate cert : certs) {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
                //
                if (certificate != null) {

                    final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal(),
                            certificate.getSerialNumber());

                    trustStoreIdentifiers.add(certId);
                }

            } //end of for certificates
        } catch (final Exception e) {
            log.info("File not found or corrupted:" + StorageFilesInformation.getTruststoreFilePath());
            // there is no trusts
        }
        return trustStoreIdentifiers;
    }

    private String getEntitynameByHostname(final String hostname) {
        return "JbossSPS_" + hostname;
    }
}
