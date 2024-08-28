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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreFileReader;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.constants.KeyStoreErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.AliasNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreFileReaderException;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;

/**
 * InitialConfiguration holds all the necessary CMP related configuration data as:
 * <p>
 * 1. RA Signer Certificate which is required while signing the response sent to entity.
 * <p>
 * 2. VendorCertificates which are External trusts, are required in verifying Digital Signature of the InitializationRequest, in case integrity of request message to be verified is through
 * VendorCredentials
 * <p>
 * 3. CACertificates which are Internal trusts, are required in verifying Digital Signature of KeyUpdateRequest
 *
 * @author tcsdemi
 *
 */
@ApplicationScoped
public class InitialConfiguration {

    private final Set<X509Certificate> vendorCertificateSet = new HashSet<>();
    private final Set<X509Certificate> caCertificateSet = new HashSet<>();
    private X509Certificate signerCertificateforEvent;
    private final Map<String, List<X509Certificate>> signerCertificateChainMap = new ConcurrentHashMap<String, List<X509Certificate>>();
    private final Map<String, X509Certificate> signerCertificateMap = new ConcurrentHashMap<>();
    private final Map<String, KeyPair> signerKeyPairMap = new HashMap<>();

    private PrivateKey privateKeyForSigningEvent;

    @Inject
    ConfigurationParamsListener configurationParamsListener;

    @Inject
    KeyStoreFileReader keyStoreFileReader;

    @Inject
    KeyStoreInfo vendorTrustStoreInfo;

    @Inject
    KeyStoreInfo caTrustStoreInfo;

    @Inject
    KeyStoreInfo signerKeyStoreInfo;

    @Inject
    Logger logger;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Will retrieve vendorCertificates, also in case vendorCertificates are empty then again certificates will be intialised for future use.
     * 
     * @return Set<X509Certificate> vendorCertificateSet- This will contain all External CAs required for verifying DigitalSignature of the RequestMessage
     * @throws InvalidInitialConfigurationException
     *             This exception is thrown when there is any error while loading keystore file.
     */
    public Set<X509Certificate> getVendorCertificateSet() throws InvalidInitialConfigurationException {
        try {
            if (vendorCertificateSet.isEmpty()) {
                initializeVendorCertificates();
            }
        } catch (final KeyStoreException keyStoreException) {
            throwCustomException(ErrorMessages.INVALID_KEYSTORE, keyStoreException);
        }
        return vendorCertificateSet;
    }

    /***
     * Will retrieve caCertificates, also in case caCertificates are empty then again certificates will be intialised for future use.
     * 
     * @return Set<X509Certificate> caCertificateSet- This will contain all Internal CA certificates as a List.
     * 
     * @throws InvalidInitialConfigurationException
     *             This exception is thrown when there is any error while loading keystore file
     */
    public Set<X509Certificate> getCaCertificateSet() throws InvalidInitialConfigurationException {

        try {
            if (caCertificateSet.isEmpty()) {
                initializeCACertificates();
            }
        } catch (final KeyStoreException keyStoreException) {
            throwCustomException(ErrorMessages.INVALID_KEYSTORE, keyStoreException);
        }
        return caCertificateSet;
    }

    /**
     * Will retrieve signerCertificate, also in case signerCertificate is null or not initialized due to some reasons then again show certificates will be intialised for future use.
     * 
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name.
     * @return X509Certificate signerCertificate This is actual RA certificate which will be used for signing responses and also will be part of the extraCertificates filed in ResponseMessage sent to
     *         entity.
     * @throws InvalidInitialConfigurationException
     *             This exception is thrown when there is any error in verifying the integrity of the certificate. Any generalSecurityException will be wrapped to InvalidInitialConfiguration
     */
    public X509Certificate getSignerCertificate(final String keyStoreAlias) throws InvalidInitialConfigurationException {

        String issuerName = keyStoreAlias;
        if (issuerName == null || issuerName.isEmpty()) {
            issuerName = configurationParamsListener.getKeyStoreAlias();
        }
        try {
            if (!signerCertificateMap.containsKey(issuerName)) {
                logger.info("Reading Signer Certificate from keystore by alias name {}" , issuerName);
                initializeSignerInfo(issuerName);
            }

        } catch (final GeneralSecurityException generalSecurityException) {
            throwCustomException(ErrorMessages.AUTH_FAILED, generalSecurityException);
        }
        final X509Certificate signerCertificate = signerCertificateMap.get(issuerName);
        logger.info("SignerCert is set and is being returned.");
        return signerCertificate;
    }

    /**
     * This method is used to get the Signer Certificate which is used to sign the Request Messages. If the Signer Certificate is null, then it will call method which read certificate from the key
     * store.
     * 
     * @return X509Certificate(signerCertificate)
     * @throws InvalidInitialConfigurationException
     *             is thrown if any error occurs while fetching SignerCertificate from keystore.
     */
    public X509Certificate getCertificateforEventSigning() throws InvalidInitialConfigurationException {
        try {
            if (signerCertificateforEvent == null) {
                logger.info("Initializaing signerCertificate.");
                initializeSignerInfoforEvent();
            }
        } catch (final AliasNotFoundException aliasNotFoundException) {
            throwCustomException(KeyStoreErrorMessages.ALIAS_NOT_FOUND, aliasNotFoundException);
        } catch (final KeyStoreFileReaderException keyStoreFileReaderException) {
            throwCustomException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE, keyStoreFileReaderException);
        }
        logger.info("SignerCert is set and is being returned.");
        return signerCertificateforEvent;
    }

    /**
     * This methods returns public/private keyPair of RA service group.
     * 
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name.
     * @return KeyPair signerKeyPair
     * @throws InvalidInitialConfigurationException
     *             This exception is thrown when there is any error while loading keystore file
     */
    public KeyPair getKeyPair(final String keyStoreAlias) throws InvalidInitialConfigurationException {

        String issuerName = keyStoreAlias;
        KeyPair signerKeyPair = null;
        if (issuerName == null || issuerName.isEmpty()) {
            issuerName = configurationParamsListener.getKeyStoreAlias();
        }
        try {

            if (!signerKeyPairMap.containsKey(issuerName)) {
                logger.info("Reading Signer key pair from keystore by alias name {}" , issuerName);
                initializeSignerInfo(issuerName);
            }
        } catch (final GeneralSecurityException generalSecurityException) {
            throwCustomException(ErrorMessages.AUTH_FAILED, generalSecurityException);
        }

        signerKeyPair = signerKeyPairMap.get(issuerName);
        return signerKeyPair;
    }

    /**
     * This class will return necessary trusts whether external trusts or internal trusts based on the reuqestType i.e IR or KUR. for eg: In case of IR trusts returned will be VendorCerts(External
     * trusts) and in case of KUR trusts will be CA certificates (InternalTrusts).
     * 
     * @param requestType
     * @return Set<X509Certificate> trustCertificateSet
     * @throws InvalidInitialConfigurationException
     *             -This exception will be thrown in case any other requestType is sent as an input parameter
     */
    public Set<X509Certificate> getTrustedCerts(final int requestType) throws InvalidInitialConfigurationException {
        Set<X509Certificate> trustCertificateSet = null;

        switch (requestType) {
        case Constants.TYPE_INIT_REQ:
            trustCertificateSet = getVendorCertificateSet();
            break;

        case Constants.TYPE_KEY_UPDATE_REQ:
            trustCertificateSet = getCaCertificateSet();
            break;

        default:
            logger.error("Initial Message stored in DB is neither Initialization Request nor Key update Request hence ", "trusted Certificates are empty.");
            throw new InvalidInitialConfigurationException(ErrorMessages.IMPROPER_INITIAL_MESSAGE);
        }
        return trustCertificateSet;
    }

    /**
     * This method will retrieve RACertificateChain i.e complete certificate chain of the signerCertificate. This chain is sent back to entity as list of ExtraCertificates as a part of ResonseMessage.
     * 
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name.
     * @return List<X509Certificate> signerCertificateChain- Contains certificate chain till RootCA of the Signer Certificate
     * @throws InvalidInitialConfigurationException
     *             -Thrown in case any error occured while building certificate chain
     */
    public List<X509Certificate> getRACertificateChain(final String keyStoreAlias) throws InvalidInitialConfigurationException {

        String issuerName = keyStoreAlias;
        List<X509Certificate> signerCertificateChain = null;
        if (issuerName == null || issuerName.isEmpty()) {
            issuerName = configurationParamsListener.getKeyStoreAlias();
        }
        try {

            if (!signerCertificateChainMap.containsKey(issuerName)) {
                logger.info("Reading RA Certificate chain from keystore by alias name {}" , issuerName);
                initializeSignerInfo(issuerName);
            }
        } catch (final GeneralSecurityException generalSecurityException) {
            throwCustomException(ErrorMessages.AUTH_FAILED, generalSecurityException);
        }

        signerCertificateChain = signerCertificateChainMap.get(issuerName);
        logger.info("RA certificate chain is established.");
        return signerCertificateChain;

    }

    /**
     * This method is used to get private key from the Signer Certificate
     * 
     * @return SignerCertificate PrivateKey
     * @throws InvalidInitialConfigurationException
     *             is thrown if any error occurs while fetching privatekey from signerCertificate.
     */
    public PrivateKey getPrivateKeyForSigning() throws InvalidInitialConfigurationException {
        try {
            if (privateKeyForSigningEvent == null) {
                initializeSignerInfoforEvent();
            }
        } catch (final AliasNotFoundException aliasNotFoundException) {
            throwCustomException(KeyStoreErrorMessages.ALIAS_NOT_FOUND, aliasNotFoundException);
        } catch (final KeyStoreFileReaderException keyStoreFileReaderException) {
            throwCustomException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE, keyStoreFileReaderException);

        }
        return privateKeyForSigningEvent;
    }

    private void throwCustomException(final String errorMessage, final Throwable cause) throws InvalidInitialConfigurationException {
        logger.error(errorMessage);
        logger.debug("Exception Stacktrace:  ", cause);
        throw new InvalidInitialConfigurationException(errorMessage, cause);

    }

    private void initializeVendorCertificates() throws KeyStoreException {
        vendorTrustStoreInfo.setFilePath(configurationParamsListener.getVendorCertPath());
        logger.info("Vendor Cert Path is" + configurationParamsListener.getVendorCertPath());
        vendorTrustStoreInfo.setKeyStoreType(StringUtility.toKeyStoreType(configurationParamsListener.getVendorTrustStoreFileType()));
        logger.info("Vendor Trust Store file Path is" + configurationParamsListener.getVendorTrustStoreFileType());
        vendorTrustStoreInfo.setPassword(System.getProperty(JBOSSVaultConstants.VENDOR_TRUST_AUTHENTICATION_CODE));
        vendorCertificateSet.addAll(keyStoreFileReader.readCertificates(vendorTrustStoreInfo));
    }

    private void initializeCACertificates() throws KeyStoreException {
        caTrustStoreInfo.setFilePath(configurationParamsListener.getCACertPath());
        logger.info("CA Cert Path is" + configurationParamsListener.getCACertPath());
        caTrustStoreInfo.setKeyStoreType(StringUtility.toKeyStoreType(configurationParamsListener.getCATrustStoreFileType()));
        logger.info("CA Trust Store Path is" + configurationParamsListener.getCATrustStoreFileType());
        caTrustStoreInfo.setPassword(System.getProperty(JBOSSVaultConstants.CA_TRUST_AUTHENTICATION_CODE));
        caCertificateSet.addAll(keyStoreFileReader.readCertificates(caTrustStoreInfo));
    }

    private void initializeSignerInfo(final String issuerName) throws GeneralSecurityException, InvalidInitialConfigurationException {
        try {
            signerKeyStoreInfo.setFilePath(configurationParamsListener.getKeyStorePath());
            logger.info("Key Store Path is {}", configurationParamsListener.getKeyStorePath());
            signerKeyStoreInfo.setKeyStoreType(StringUtility.toKeyStoreType(configurationParamsListener.getKeyStoreFileType()));
            logger.info("Key Store file type is {}", configurationParamsListener.getKeyStoreFileType());
            signerKeyStoreInfo.setAliasName(issuerName);
            logger.info("Key Store alias is {}" , issuerName);
            signerKeyStoreInfo.setPassword(System.getProperty(JBOSSVaultConstants.RA_KEYSTORE_AUTHENTICATION_CODE));
            final X509Certificate signerCertificate = (X509Certificate) keyStoreFileReader.readCertificate(signerKeyStoreInfo);
            final Certificate[] jksCertChain = keyStoreFileReader.readCertificateChain(signerKeyStoreInfo);

            final List<X509Certificate> signerCertificateChain = new ArrayList<>();
            for (final Certificate eachJksCert : jksCertChain) {
                signerCertificateChain.add((X509Certificate) eachJksCert);
            }
            final PrivateKey privateKeyForSigning = keyStoreFileReader.readPrivateKey(signerKeyStoreInfo);

            final KeyPair signerKeyPair = new KeyPair(signerCertificate.getPublicKey(), privateKeyForSigning);

            signerCertificateMap.put(issuerName, signerCertificate);
            signerCertificateChainMap.put(issuerName, signerCertificateChain);
            signerKeyPairMap.put(issuerName, signerKeyPair);

            logger.info("signerCertificate for the issuer [{}] is [{}]", issuerName, signerCertificateMap.get(issuerName).getSubjectDN());

            final StringBuilder signerCertDnChain = new StringBuilder();
            for (X509Certificate certificate : signerCertificateChainMap.get(issuerName)) {
                signerCertDnChain.append(certificate.getSubjectDN().toString());
                signerCertDnChain.append(System.getProperty("line.separator"));
            }
            logger.info("signerCertificateChain for the issuer [{}] is [{}] ", issuerName, signerCertDnChain);

        } catch (final KeyStoreFileReaderException keyStoreFileReaderException) {
            throwCustomException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE, keyStoreFileReaderException);
        } catch (final AliasNotFoundException aliasNotFoundException) {
            throwCustomException(KeyStoreErrorMessages.ALIAS_NOT_FOUND, aliasNotFoundException);
        }
    }

    /**
     * Will re-initialize vendor certificates(External Trusts).
     * 
     * @throws InvalidInitialConfigurationException
     *             in case of configuration data is invalid or is not consistent
     */
    public synchronized void reInitializeVendorCertificates() throws InvalidInitialConfigurationException {
        try {
            initializeVendorCertificates();
        } catch (final KeyStoreException keyStoreException) {
            throwCustomException(ErrorMessages.INVALID_KEYSTORE, keyStoreException);
        }
    }

    /**
     * Will re-initialize CA certificates(Internal Trusts).
     * 
     * @throws InvalidInitialConfigurationException
     *             in case of configuration data is invalid or is not consistent
     */
    public synchronized void reInitializeCACertificates() throws InvalidInitialConfigurationException {
        try {
            initializeCACertificates();
        } catch (final KeyStoreException keyStoreException) {
            throwCustomException(ErrorMessages.INVALID_KEYSTORE, keyStoreException);
        }
    }

    private void initializeSignerInfoforEvent() throws AliasNotFoundException, KeyStoreFileReaderException {
        signerKeyStoreInfo.setFilePath(configurationParamsListener.getKeyStorePath());
        logger.debug("Key Store Path is" + configurationParamsListener.getKeyStorePath());
        signerKeyStoreInfo.setKeyStoreType(StringUtility.toKeyStoreType(configurationParamsListener.getKeyStoreFileType()));
        logger.debug("Key Store file type is" + configurationParamsListener.getKeyStoreFileType());
        signerKeyStoreInfo.setAliasName(configurationParamsListener.getCMPRAInfraCertAliasName());
        logger.debug("Key Store alias is" + configurationParamsListener.getCMPRAInfraCertAliasName());
        signerKeyStoreInfo.setPassword(System.getProperty(JBOSSVaultConstants.RA_KEYSTORE_AUTHENTICATION_CODE));
        signerCertificateforEvent = (X509Certificate) keyStoreFileReader.readCertificate(signerKeyStoreInfo);

        privateKeyForSigningEvent = keyStoreFileReader.readPrivateKey(signerKeyStoreInfo);
    }

}
