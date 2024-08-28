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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper.channelMode;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateValidationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.CertHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CSRAttributesHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CertHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CsrHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialReaderFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.itpf.security.keymanagement.exception.KeyGeneratorException;

public class CertificateManager {
    private static final Logger log = LogManager.getLogger(CertificateManager.class);
    // wrapper to call service REST or remote EJB
    final private CredMServiceWrapper service;

    // data for certificate
    private CertHandler certHandler = null;;
    private Certificate[] certChain = null;
    private KeyPair keyPair = null;
    private PKCS10CertificationRequest csr = null;

    // store info about the ceritficate to be revoked
    private CredentialManagerCertificateIdentifier revokeCertId = null;

    /**
     *
     * @param serviceWrapper
     */
    public CertificateManager(final CredMServiceWrapper serviceWrapper) {
        this.service = serviceWrapper;
    }

    /**
     * generateKey
     *
     * @param profileInfo
     * @throws IssueCertificateException
     */
    public void generateKey(final CredentialManagerProfileInfo profileInfo) throws IssueCertificateException {

        /**
         * Create Key Pair
         */
        this.setKeyPair(null);
        try {
            this.setKeyPair(KeyGenerator.getKeyPair(profileInfo.getKeyPairAlgorithm().getName(), profileInfo.getKeyPairAlgorithm().getKeySize()));
        } catch (final KeyGeneratorException e) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_CREATE_KEYPAIR, profileInfo.getSubjectByProfile().getDnQualifier());
            throw (new IssueCertificateException("Key Pair not generated"));
        }
    }

    /**
     * generateCSR
     *
     * @param entity
     * @param profileInfo
     * @param certificateExtensionInfo
     * @throws IssueCertificateException
     */
    public void generateCSR(final CredentialManagerEntity entity, final CredentialManagerProfileInfo profileInfo,
                            final CredentialManagerCertificateExtension certificateExtensionInfo)
            throws IssueCertificateException {

        if (this.getKeyPair() == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_KEYPAIR);
            throw new IssueCertificateException("Error generating CSR: keyPair is Null");
        }

        /**
         * Create CSR
         */
        final CsrHandler csrHandler = new CsrHandler();
        final CSRAttributesHandler csrAttributesHandler = new CSRAttributesHandler();
        final Attribute[] attributes;

        attributes = csrAttributesHandler.generateAttributes(profileInfo, certificateExtensionInfo);

        this.csr = csrHandler.getCSR(entity, profileInfo.getSignatureAlgorithm().getName().trim(), this.getKeyPair(), attributes);
        if (this.csr == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_CREATE_CSR, entity.getName());
            throw new IssueCertificateException("Error generating CSR: CSR not created");
        }
    }

    /**
     * generateCertificate
     *
     * @param entityName
     * @param profileInfo
     * @throws IssueCertificateException
     * @throws OtpNotValidException
     * @throws OtpExpiredException
     */
    public void generateCertificate(final String entityName, final CredentialManagerProfileInfo profileInfo, final boolean certificateChain,
                                    final String otp)
            throws IssueCertificateException, OtpExpiredException, OtpNotValidException {

        if (this.csr == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CSR);
            throw new IssueCertificateException("CSR cannot be null");
        }

        /**
         * Get Certificate
         */
        this.setCertHandler(new CertHandler());
        try {
            final Certificate[] chain = this.getCertHandler().getSignedCertificate(this.service, this.csr, entityName, certificateChain, otp);
            this.setCertChain(chain);
            if (this.getCertChain() == null) {
                log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CERTIFICATE, entityName);
                throw (new IssueCertificateException("Certificate generated is NULL"));
            }
        } catch (final CertificateEncodingException e) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_ENCODE_CERT);
            throw new IssueCertificateException("certHandler getSignedCertificate exception");
        }
    }

    /**
     * generateCertificateRestChannel
     *
     * @throws IssueCertificateException
     */
    public void generateCertificateRestChannel() throws IssueCertificateException {

        if (this.csr == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_RESTCSR);
            throw new IssueCertificateException("generateCertificateRestChannel csr null");
        }

        /**
         * Get Certificate
         */
        this.setCertHandler(new CertHandler());
        final CredentialManagerX509Certificate[] certString;
        certString = this.service.getCertificate(this.csr);

        if (certString == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CERTHANDLER);
            throw (new IssueCertificateException("Cert is NULL"));
        }

        final Certificate[] certificates = new Certificate[certString.length];
        int countCerts = 0;
        for (final CredentialManagerX509Certificate x509Cert : certString) {
            certificates[countCerts] = x509Cert.retrieveCertificate();
            countCerts++;
        }

        this.setCertChain(certificates);

        if (this.getCertChain() == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CERTHANDLER);
            throw (new IssueCertificateException("Cert is NULL"));
        }
    }

    /**
     * WriteKeyAndCertificate
     *
     * @param ksInfoList
     * @throws IssueCertificateException
     */
    public void writeKeyAndCertificate(final List<KeystoreInfo> ksInfoList) throws IssueCertificateException {

        if (this.getKeyPair() == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_KEYPAIR);
            throw new IssueCertificateException("writeKeyAndCertificate keyPair null");
        }
        if (this.getCertChain() == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CSR);
            throw new IssueCertificateException("writeKeyAndCertificate chain null");
        }

        if (this.getCertHandler() == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CERTHANDLER);
            throw new IssueCertificateException("certHandler is NULL");
        }
        /**
         * write Key and Certificate
         */
        try {
            for (final KeystoreInfo ksInfo : ksInfoList) {
                this.getCertHandler().writeKeyAndCertificate(this.getCertChain(), this.getKeyPair(), ksInfo);
            }
        } catch (final CertHandlerException e) {
            throw new IssueCertificateException("certHandler writeKeyAndCertificate exception");
        }

    } // end of WriteKeyAndCertificate

    /**
     * checkCertificateValidity
     *
     * @param keyStoreCert
     * @param xmlSubject
     * @param entity
     * @param profileInfo
     * @return
     * @throws CertificateValidationException
     */
    public Boolean checkCertificateValidity(final KeystoreInfo keyStoreCert, final String xmlSubject, final CredentialManagerEntity entity,
                                            final boolean firstDailyRun, final CredentialManagerPIBParameters parameters)
            throws CertificateValidationException {

        String storeFilePath = null;
        String keyFilePath = null;

        /**
         * Validate settings into keyStoreCert
         */
        if (keyStoreCert.getCertificateLocation() != null && !keyStoreCert.getCertificateLocation().isEmpty()) {
            storeFilePath = keyStoreCert.getCertificateLocation();

            // check if also the key is present
            if (keyStoreCert.getPrivateKeyLocation() == null || keyStoreCert.getPrivateKeyLocation().isEmpty()) {
                throw new CertificateValidationException("checkCertificateValidation: key file location not set!");
            }
            // set the key path
            keyFilePath = keyStoreCert.getPrivateKeyLocation();

            if (keyStoreCert.getKeyAndCertLocation() != null && !keyStoreCert.getKeyAndCertLocation().isEmpty()) {
                log.error(ErrorMsg.API_ERROR_BUSINESS_CERTIFICATE_MULTIPLELOC, entity.getName());
                throw new CertificateValidationException("checkCertificateValidation: multiple file location setting found!");
            }
        } else if (keyStoreCert.getKeyAndCertLocation() != null && !keyStoreCert.getKeyAndCertLocation().isEmpty()) {
            storeFilePath = keyStoreCert.getKeyAndCertLocation();
        } else {
            log.error(ErrorMsg.API_ERROR_BUSINESS_CERTIFICATE_MISSINGLOC, entity.getName());
            throw new CertificateValidationException("checkCertificateValidation: file location not set!");
        }

        if (keyStoreCert.getAlias() == null) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_ALIASKS, xmlSubject);
            throw new CertificateValidationException("checkCertificateValidation: alias not set!");
        }

        System.out.println("checkCertificateValidity " + storeFilePath);
        log.debug("checkCertificateValidity " + storeFilePath);

        /**
         * check if the keystore exists
         */
        final File storeFile = new File(storeFilePath);
        if (!storeFile.exists()) {
            log.info("KEYSTORE DOES'N EXIST " + storeFilePath);
            return false;
        }

        /**
         * check also the key file (if need)
         */
        if (keyFilePath != null) {
            final File keyFile = new File(keyFilePath);
            if (!keyFile.exists()) {
                log.info("KEYFILE DOES'N EXIST " + keyFilePath);
                return false;
            }
        }

        /**
         * Read certificate from Storage
         */
        Certificate certificate = null;

        final CredentialReaderFactory crf = new CredentialReaderFactory();
        try {
            final CredentialReader credRKS = crf.getCredentialreaderInstance(StorageFormatUtils.getCertFormatString(keyStoreCert.getCertFormat()),
                    storeFilePath, keyStoreCert.getKeyStorePwd());

            certificate = credRKS.getCertificate(keyStoreCert.getAlias());

            if (certificate == null) {
                log.info("CERTIFICATE IS NULL " + storeFilePath);
                return false; // certificate not found
            }

        } catch (final StorageException e) {

            log.error(ErrorMsg.API_ERROR_BUSINESS_GET_CERTKS, entity.getName());
            //e.printStackTrace();
            return false; // invalid certificate format
        }

        /**
         * Certificate validation
         */
        try {
            final boolean value = this.isCertificateValid(certificate, xmlSubject, entity, firstDailyRun, parameters);
            if (value == false) {
                log.info("BouNCYCaSTle CHECK " + storeFilePath);
            }
            return value;
        } catch (final CertificateValidationException e) {
            throw new CertificateValidationException(e.getMessage());
        }

    } // end of checkCertificateValidation

    /**
     *
     * @param cert
     * @param xmlSubject
     * @param entity
     * @param profileInfo
     * @return
     * @throws CertificateValidationException
     */
    public Boolean isCertificateValid(final Certificate cert, final String xmlSubject, final CredentialManagerEntity entity,
                                      final boolean firstDailyRun, final CredentialManagerPIBParameters parameters)
            throws CertificateValidationException {

        /**
         * Certificate format conversion to X509
         */
        X509Certificate certificate = null;
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
            certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (final CertificateException e) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_CREATE_CERTSTREAM, entity.getName());
            throw (new CertificateValidationException("isCertificateValid: " + e.getMessage()));
        }

        /**
         * Check LDAP format (Subject)
         */

        LdapName xmlLdapName = null;
        LdapName certLdapName = null;
        try {
            xmlLdapName = new LdapName(xmlSubject);
            certLdapName = CertificateUtils.buildDNfromOids(certificate.getSubjectX500Principal().getName());
        } catch (final InvalidNameException e) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_CREATE_LDAPNAME, entity.getName());
            throw new CertificateValidationException("isCertificateValid: " + e.getMessage());
        }

        /**
         * Check xmlSubject is included in the certificate
         */
        final String[] localString = xmlLdapName.toString().split(",");
        log.debug("checkLdapName, certLdapName: " + certLdapName.toString());
        for (final String s : localString) {
            log.debug("checkLdapName, xmlLdapName entry: " + s);
            // DN Qualifier should be not used to invalidate the certificate
            // https://jira-nam.lmera.ericsson.se/browse/TORF-150963
            if (s.contains("DN=")) {
                continue;
            }
            if (!certLdapName.toString().contains(s.trim())) {
                log.debug("CertificateNotValid: ldap name : " + entity.getName());
                return false;
            }
        }

        /**
         * Validity Period
         */

        log.debug("Is the first run of the day: " + firstDailyRun);
        try {
            // force validity expires some time before the actual expiration date, in order to issue a new one
            // before the old one becomes invalid
            List<String> warningsList = new ArrayList<String>();

            final String warningString = parameters.getServiceCertAutoRenewalWarnings();
            warningsList = Arrays.asList(warningString.split(","));

            CertificateUtils.checkDateValidity(certificate, firstDailyRun, warningsList, entity.getName(),
                    parameters.getServiceCertAutoRenewalTimer(), service);
        } catch (final CertificateExpiredException e) {
            // throw new CertificateValidationException("isCertificateValid: CertificateExpiredException: " + e.getMessage());
            log.debug("CertificateNotValid: expired  : " + entity.getName());
            if (!parameters.isServiceCertAutoRenewalEnabled()) {
                log.warn("Attention, the certificate for " + entity.getName() + " is not valid but renewal is set to false!");
                this.service.printErrorOnSystemRecorder("Certificate Expired", ErrorSeverity.WARNING, "Credential Manager CLI", entity.getName(),
                        "AutoRenewal is not set");
            } else {
                return false;
            }
        } catch (final CertificateNotYetValidException e) {
            // throw new CertificateValidationException("isCertificateValid: CertificateNotYetValidException: " + e.getMessage());
            log.debug("CertificateNotValid: notYetValid  : " + entity.getName());
            System.out.println("CertificateNotValid: notYetValid  : " + entity.getName());
            return false;
        }

        /**
         * Check LDAP format (Issuer Subject)
         */

        LdapName issuerLdapName = null;
        LdapName certIssuerLdapName = null;
        try {
            issuerLdapName = new LdapName(entity.getIssuerDN().retrieveSubjectDN());
            certIssuerLdapName = CertificateUtils.buildDNfromOids(certificate.getIssuerX500Principal().getName());
        } catch (final InvalidNameException e) {
            log.error(ErrorMsg.API_ERROR_BUSINESS_CREATE_LDAPNAME, entity.getIssuerDN().getCommonName());
            throw new CertificateValidationException("isCertificateValid: " + e.getMessage());
        }

        /**
         * Check Issuer Subject is included in the certificate
         */
        final String[] issuerString = issuerLdapName.toString().split(",");
        log.debug("checkIssuerLdapName, certIssuerLdapName: " + certIssuerLdapName.toString());
        for (final String s : issuerString) {
            log.debug("checkIssuerLdapName, issuerLdapName entry: " + s);
            // DN Qualifier should be not used to invalidate the certificate
            // https://jira-nam.lmera.ericsson.se/browse/TORF-150963
            if (s.contains("DN=")) {
                continue;
            }
            if (!certIssuerLdapName.toString().contains(s.trim())) {
                log.debug("CertificateNotValid: issuer ldap name : " + entity.getIssuerDN().getCommonName());
                return false;
            }
        }

        /**
         * check EntityStatus
         *
         */
        /*
         * If Entity Status = ACTIVE then CredMCli shall verify if currently stored Certificate Status is ACTIVE or INACTIVE: if so it will do
         * nothing, else it shall ISSUE a new Certificate
         *
         * If Entity Status = INACTIVE then CredMCli shall ISSUE a new certificate
         *
         * If Entity Status = REISSUE then CredMCli shall ISSUE a new certificate and then it shall REVOKE the certificate which was previously stored
         * in the KeyStore folder (if nothing is stored in the KeyStore folder then not exsiting it shall not revoke anything). Note that previous
         * certificate serial number to be revoked should be saved before issuing the new certificate
         */
        log.debug("Entity  : " + entity.getName() + " - Status : " + entity.getEntityStatus());

        // NEW, ACTIVE, INACTIVE, REISSUE, DELETED
        switch (entity.getEntityStatus()) {

            case NEW:
            case INACTIVE:
                // a new certificate must be issued
                return false;
            //break;

            case REISSUE:
                // a new certificate must be issued and the old one will be revoked
                final CredentialManagerCertificateIdentifier certId = CertificateUtils.buildIdentifier(certificate);
                this.setRevokeCertId(certId);
                return false;
            //break;

            case ACTIVE:
                /**
                 * check current certificate status
                 */
                boolean flagMyCertFound = false;

                if (this.service.getMode().equals(channelMode.REST_CHANNEL)) {
                    //this check is not available on REST channel
                    // but in this case we consider the test passed
                    flagMyCertFound = true;
                } else {
                    // retrieve from service the list of active certificates (shoul dbe just one!)
                    final List<CredentialManagerX509Certificate> activeCertificates = this.service.listActiveCertificates(entity.getName());
                    if (activeCertificates != null) {

                        // !!!!!!!!!!!!!!!!!!!!!!!!!!!
                        // TMP cause the PKI always return empty list
                        // !!!!!!!!!!!!!!!!!!!!!!!!!!!
                        //if (activeCertificates.isEmpty()) {
                        //    log.debug("TMP: list empty, certificate should be re issued, but we dont");
                        //    System.out.println("TMP: list empty, certificate should be re issued, but we dont");
                        //    return true;
                        //}
                        // TODO remove when the pki implementation is ready

                        for (final CredentialManagerX509Certificate c : activeCertificates) {
                            //check if the active certificate is the one i have
                            final BigInteger sn1 = certificate.getSerialNumber();
                            final BigInteger sn2 = c.retrieveCertificate().getSerialNumber();
                            if (sn1.equals(sn2)) {
                                flagMyCertFound = true;
                            }
                        }
                    }
                }
                return flagMyCertFound;
            //break;

            default:
                //DELETE, it should never be present
                break;
        }

        return true;

    } // end of isCertificateValid

    /**
     * deleteKeystores
     *
     * @param ksInfoList
     * @throws IssueCertificateException
     * @throws CertificateValidationException
     */

    public void clearKeystores(final List<KeystoreInfo> ksInfoList) {

        this.setCertHandler(new CertHandler());

        //
        // call deleteKeystoreEntry for each keystore
        // this will not delete the entire keystore but only the entry defined by the alias
        //
        for (final KeystoreInfo ksInfo : ksInfoList) {
            try {
                this.certHandler.clearKeystore(ksInfo);
            } catch (final CertHandlerException e) {
                // something wrong in the keystore
                //e.printStackTrace();
                System.out.println("clearKeystores: DELETE keystore");
                ksInfo.delete();
            }
        }

    }

    /**
     * revokeCertificate
     *
     * @return
     */
    public Boolean revokeCertificate() {

        Boolean result = null;

        final CredentialManagerCertificateIdentifier revokeId = this.getRevokeCertId();
        if (revokeId != null) {
            result = this.service.revokeCertificateById(revokeId);
        }
        return result;

    }

    //
    // getters and setters

    /**
     * @return the certHandler
     */
    public CertHandler getCertHandler() {
        return this.certHandler;
    }

    /**
     * @param certHandler
     *            the certHandler to set
     */
    public void setCertHandler(final CertHandler certHandler) {
        this.certHandler = certHandler;
    }

    /**
     * @return the cert
     */
    public Certificate[] getCertChain() {
        return this.certChain;
    }

    /**
     * @param cert
     *            the cert to set
     */
    public void setCertChain(final Certificate[] cert) {
        this.certChain = cert;
    }

    /**
     * @return the keyPair
     */
    public KeyPair getKeyPair() {
        return this.keyPair;
    }

    /**
     * @param keyPair
     *            the keyPair to set
     */
    public void setKeyPair(final KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * @return the revokeCertId
     */
    public CredentialManagerCertificateIdentifier getRevokeCertId() {
        return this.revokeCertId;
    }

    /**
     * @param revokeCertId
     *            the revokeCertId to set
     */
    public void setRevokeCertId(final CredentialManagerCertificateIdentifier revokeCertId) {
        this.revokeCertId = revokeCertId;
    }

} // end of class
