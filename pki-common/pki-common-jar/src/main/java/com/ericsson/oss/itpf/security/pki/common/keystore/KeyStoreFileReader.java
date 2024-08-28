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

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.ericsson.oss.itpf.security.pki.common.keystore.exception.*;

/**
 * This is an interface for reading different type of KeyStore info files and provides below operations.
 * <ul>
 * <li>getCertChain gets the certificate[] from the keyStore based on keyStoreInfo</li>
 * 
 * <li>getCertificate gets the certificate from the keyStore based on keyStoreInfo</li>
 * 
 * <li>getPrivateKey returns private key by using keyStoreinfo</li>
 * 
 * </ul>
 * 
 * @author xjagcho
 */
public interface KeyStoreFileReader {
    /**
     * This method returns certificate chain from KeyStore.
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

    Certificate[] readCertificateChain(final KeyStoreInfo keyStoreInfo) throws AliasNotFoundException, CertificateChainNotFoundException, KeyStoreNotLoadedException, CertificateNotLoadedException,
            InvalidKeyStoreDataException;

    /**
     * This method returns certificate from KeyStore.
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
    Certificate readCertificate(final KeyStoreInfo keyStoreInfo) throws AliasNotFoundException, CertificateNotFoundException, InvalidKeyStoreDataException, KeyStoreNotLoadedException,
            CertificateNotLoadedException;

    /**
     * This method returns private key from KeyStore.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName.
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
    PrivateKey readPrivateKey(final KeyStoreInfo keyStoreinfo) throws AliasNotFoundException, InvalidKeyStoreDataException, KeyStoreNotLoadedException, CertificateNotLoadedException,
            PrivateKeyReaderException;

    /**
     * This method returns Set of certificates from the KeyStore.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName.
     * @return set of X509Certificates
     * @throws KeyStoreException
     */
    Set<X509Certificate> readCertificates(KeyStoreInfo keyStoreInfo) throws KeyStoreException;

    /**
     * This method returns all aliases as a list from the Key Store.
     * 
     * @param keyStoreInfo
     *            contains keystoreType, password, aliasName and filePath.
     * @throws InvalidKeyStoreDataException
     *             is thrown if the provided data for loading Key Store is wrong.
     */
    List<String> getAllAliases(final KeyStoreInfo keyStoreInfo) throws InvalidKeyStoreDataException;
}
