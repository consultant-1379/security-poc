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
package com.ericsson.oss.itpf.security.pki.common.keystore;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.keystore.constants.KeyStoreErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.*;

/**
 * This class used to get the Certificate chain, Certificate and private key...etc from JKS/PKCS12 KeyStore.
 * 
 * @author xjagcho
 * 
 */
public class JksPkcs12KeyStoreFileReader implements KeyStoreFileReader {

    private static final Logger logger = LoggerFactory.getLogger(JksPkcs12KeyStoreFileReader.class);

    /**
     * This method returns certificate chain from KeyStore based on the aliasName.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType, password, filePath and aliasName.
     * 
     * @return Certificate[] of the corresponding aliasName.
     * 
     * @throws AliasNotFoundException
     *             is thrown the given AliasName is not found in the KeyStore.
     * @throws CertificateChainNotFoundException
     *             is thrown if the CertificateChain for the given alias name is not found in the Key Store.
     * @throws KeyStoreNotLoadedException
     *             is thrown if the Key Store is not loaded.
     * @throws CertificateNotLoadedException
     *             is thrown if the Certificates are not loaded into Key Store.
     * @throws InvalidKeyStoreDataException
     *             is thrown if the provided data for loading Key Store is wrong.
     */

    @Override
    public Certificate[] readCertificateChain(final KeyStoreInfo keyStoreInfo)
            throws AliasNotFoundException, CertificateChainNotFoundException, KeyStoreNotLoadedException, CertificateNotLoadedException, InvalidKeyStoreDataException {
        logger.debug("Start of readCertificateChain method in JksPkcs12KeyStoreFileReader class");
        Certificate[] certChain = null;
        KeyStore keystore;
        try {
            keystore = loadKeyStore(keyStoreInfo);
            if (keystore.containsAlias(keyStoreInfo.getAliasName())) {
                certChain = keystore.getCertificateChain(keyStoreInfo.getAliasName());
            } else {
                logger.error("Alias is not found in the keystore{}", keyStoreInfo.getAliasName());
                throw new AliasNotFoundException(KeyStoreErrorMessages.ALIAS_NOT_FOUND);
            }
            if (certChain == null) {
                logger.error("Certificate chain is null");
                throw new CertificateChainNotFoundException(KeyStoreErrorMessages.CERTIFICATE_CHAIN_NOT_FOUND);
            }

        } catch (final KeyStoreException e) {
            logger.error("Caught exception while getting certChain", e);
            throw new KeyStoreNotLoadedException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE);
        }
        logger.debug("End of readCertificateChain method in JksPkcs12KeyStoreFileReader class");
        return certChain;
    }

    /**
     * This method returns certificate from KeyStore based on the aliasName.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType, password, filePath and aliasName.
     * 
     * @return Certificate is the certificate which is read from Key Store.
     * 
     * @throws AliasNotFoundException
     *             is thrown the given AliasName is not found in the Key Store.
     * @throws CertificateNotFoundException
     *             is thrown if the Certificate for the given alias name is not found in the Key Store.
     * @throws InvalidKeyStoreDataException
     *             is thrown if the provided data for loading Key Store is wrong.
     * @throws KeyStoreNotLoadedException
     *             is thrown if the Key Store is not loaded.
     * @throws CertificateNotLoadedException
     *             is thrown if the Certificates are not loaded into Key Store.
     */

    @Override
    public Certificate readCertificate(final KeyStoreInfo keyStoreInfo)
            throws AliasNotFoundException, CertificateNotFoundException, InvalidKeyStoreDataException, KeyStoreNotLoadedException, CertificateNotLoadedException {
        logger.debug("Start of readCertificate method in JksPkcs12KeyStoreFileReader class");
        Certificate certificate = null;
        KeyStore keystore;
        try {
            keystore = loadKeyStore(keyStoreInfo);
            if (keystore.containsAlias(keyStoreInfo.getAliasName())) {
                certificate = keystore.getCertificate(keyStoreInfo.getAliasName());
            } else {
                logger.error("KeyStore doesnot contains the following alias{}", keyStoreInfo.getAliasName());
                throw new AliasNotFoundException(KeyStoreErrorMessages.ALIAS_NOT_FOUND);
            }
            if (certificate == null) {
                logger.error("KeyStore doesnot contains the following alias{}", keyStoreInfo.getAliasName());
                throw new CertificateNotFoundException(KeyStoreErrorMessages.CERTIFICATE_NOT_FOUND);
            }

        } catch (final KeyStoreException e) {
            logger.error("Caught exception while getting certificate", e);
            throw new KeyStoreNotLoadedException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE);
        }
        logger.debug("End of readCertificate method in JksPkcs12KeyStoreFileReader class");
        return certificate;
    }

    /**
     * This method returns private key from KeyStore based on the alias name.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName.
     * 
     * @return PrivateKey is read from key store based on the provided aliasName.
     * @throws AliasNotFoundException
     *             is thrown the given AliasName is not found in the Key Store.
     * @throws InvalidKeyStoreDataException
     *             is thrown if the provided data for loading Key Store is wrong.
     * @throws KeyStoreNotLoadedException
     *             is thrown if the Key Store is not loaded.
     * @throws CertificateNotLoadedException
     *             is thrown if the Certificates are not loaded into Key Store.
     * @throws PrivateKeyReaderException
     *             is thrown if the private key is not read from the Key Store.
     **/
    // TODO: This returning of private key will be changed/removed once the interface design for reading, writing and storing the keys and certificates is done. User story ref : TORF-63700
    @Override
    public PrivateKey readPrivateKey(final KeyStoreInfo keyStoreinfo)
            throws AliasNotFoundException, InvalidKeyStoreDataException, KeyStoreNotLoadedException, CertificateNotLoadedException, PrivateKeyReaderException {
        logger.debug("Start of readPrivateKey method in JksPkcs12KeyStoreFileReader class");
        PrivateKey privateKey = null;
        KeyStore keystore;
        try {
            keystore = loadKeyStore(keyStoreinfo);
            if (keystore.containsAlias(keyStoreinfo.getAliasName())) {
                privateKey = (PrivateKey) keystore.getKey(keyStoreinfo.getAliasName(), keyStoreinfo.getPassword().toCharArray());
            } else {
                logger.error("KeyStore doesnot contains the following alias{}", keyStoreinfo.getAliasName());
                throw new AliasNotFoundException(KeyStoreErrorMessages.ALIAS_NOT_FOUND);
            }
        } catch (final UnrecoverableKeyException e) {
            logger.error("Caught exception while reading private key {}", e.getMessage());
            throw new PrivateKeyReaderException(KeyStoreErrorMessages.UNRECOVERABLE_KEY, e);
        } catch (final KeyStoreException | NoSuchAlgorithmException e) {
            logger.error("Caught exception while reading private key {}", e.getMessage());
            throw new PrivateKeyReaderException(KeyStoreErrorMessages.READ_PRIVATE_KEY_FAILURE, e);
        }
        logger.debug("End of readPrivateKey method in JksPkcs12KeyStoreFileReader class");
        return privateKey;
    }

    /**
     * This method is used to load the key store by using keyStoreInfo object as parameter
     * 
     * @param keyStoreInfo
     *            contains keystoreType, password, aliasName and filePath.
     * 
     * @return KeyStore is the initialized Key Store with Certificates and Keys.
     * @throws KeyStoreNotLoadedException
     *             is thrown if the Key Store is not loaded.
     * @throws CertificateNotLoadedException
     *             is thrown if the Certificates are not loaded into Key Store.
     * @throws InvalidKeyStoreDataException
     *             is thrown if the provided data for loading Key Store is wrong.
     */
    private KeyStore loadKeyStore(final KeyStoreInfo keyStoreInfo) throws KeyStoreNotLoadedException, CertificateNotLoadedException, InvalidKeyStoreDataException {
        logger.debug("Start of loadKeyStore method in JksPkcs12KeyStoreFileReader class");
        KeyStore keyStore = null;
        FileInputStream fis = null;
        try {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
            fis = new FileInputStream(keyStoreInfo.getFilePath());
            keyStore.load(fis, keyStoreInfo.getPassword().toCharArray());
        } catch (final KeyStoreException | NoSuchAlgorithmException e) {
            logger.error("Caught Exception while loading key store {}", e.getMessage());
            throw new KeyStoreNotLoadedException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE, e);
        } catch (final CertificateException e) {
            logger.error("Caught Exception while loding Certificates into KeyStore {}", e.getMessage());
            throw new CertificateNotLoadedException(KeyStoreErrorMessages.CERTIFICATE_NOT_LOADED, e);
        } catch (final IOException e) {
            logger.error("Caught Exception due to invalid data for loading Key Store : {}", e.getMessage());
            throw new InvalidKeyStoreDataException(KeyStoreErrorMessages.INVALID_KEY_STORE_DATA, e);
        } finally {
            closeInputStream(fis);
        }
        logger.debug("Start of loadKeyStore method in JksPkcs12KeyStoreFileReader class");
        return keyStore;
    }

    /**
     * @param fis
     */
    private void closeInputStream(final FileInputStream fis) throws KeyStoreNotLoadedException, CertificateNotLoadedException, InvalidKeyStoreDataException {
        if (fis != null) {
            try {
                fis.close();
            } catch (IOException e) {
                logger.error("Caught Exception while loading key store {}", e.getMessage());
                throw new KeyStoreNotLoadedException(KeyStoreErrorMessages.KEY_STORE_LOAD_FAILURE);
            }
        }
    }

    public Set<X509Certificate> readCertificates(final KeyStoreInfo keyStoreInfo) throws KeyStoreException {
        final Set<X509Certificate> certificatesFromStore = new HashSet<X509Certificate>();
        final KeyStore keystore = loadKeyStore(keyStoreInfo);
        final Enumeration<String> enumeration = keystore.aliases();

        while (enumeration.hasMoreElements()) {
            final String alias = enumeration.nextElement();
            final X509Certificate certificateFromStore = (X509Certificate) keystore.getCertificate(alias);
            certificatesFromStore.add(certificateFromStore);

        }
        return certificatesFromStore;
    }

    @Override
    public List<String> getAllAliases(final KeyStoreInfo keyStoreInfo) throws InvalidKeyStoreDataException {
        logger.debug("Start of getAllAliases method in JksPkcs12KeyStoreFileReader class");
        try {
            final List<String> aliases = new ArrayList<>();
            final KeyStore keystore = loadKeyStore(keyStoreInfo);
            final Enumeration<String> enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                aliases.add(enumeration.nextElement());
            }
            logger.debug("getAllAliases method returns [{}]", aliases);
            return aliases;
        } catch (KeyStoreException e) {
            logger.error("Caught exception while reading private key {}", e.getMessage());
            throw new InvalidKeyStoreDataException(KeyStoreErrorMessages.READ_ALIASES_FAILURE, e);
        }
    }

}
