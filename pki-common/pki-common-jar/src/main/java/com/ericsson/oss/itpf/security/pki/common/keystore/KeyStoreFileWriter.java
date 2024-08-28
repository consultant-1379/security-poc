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

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * This is an interface for writing/adding certificate/s data into KeyStore based on input format given in keyStoreInfo.
 * <ul>
 * <li>createCertificateKeyStore writes the certificate/s data into keyStore based on keyStoreInfo</li>
 * 
 * <li>addChaintoKeyStoreWithKey adds the certificate/s data the keyStore based on keyStoreInfo along with private key</li>
 * 
 * </ul>
 * 
 * @author xpranma
 */
public interface KeyStoreFileWriter {

    /**
     * Method to create KeyStore and store certificates in it. The KeyStore type is provided in keyStoreInfo along with its password.
     * 
     * @param certificates
     *            List of Certificates to be stored in KeyStore
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName.
     * @return resource
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     */
    Resource createCertificateKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException,
            NoSuchProviderException;

    /**
     * Method to add certificate chain into KeyStore along with private key and certificates. If private key is not available then certificates are added directly.
     * 
     * @param certificates
     *            List of Certificates to be stored in KeyStore
     * @param keyStoreInfo
     *            KeyStoreInfo that contains information of end entity certificate
     * @param keyStoreFileData
     *            certificate data along with its private key
     * @return resource
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     * @throws UnrecoverableKeyException
     *             in case key cannot be recovered from KeyStore
     */
    Resource addCertificateChainToKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException;

    /**
     * Method to create KeyStore and store certificates in it. The KeyStore type is provided in keyStoreInfo along with its password. This method will return the name of the created KeyStore file.
     * 
     * @param certificates
     *            List of Certificates to be stored in KeyStore
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName.
     * @return String name of the KeyStoreFile.
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     */
    String createCertKeyStore(List<Certificate> certificates, KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * Method to add certificate chain into KeyStore along with private key and certificates. If private key is not available then certificates are added directly. This method will return the name of
     * the KeyStore file.
     * 
     * @param certificates
     *            List of Certificates to be stored in KeyStore
     * @param keyStoreInfo
     *            KeyStoreInfo that contains information of end entity certificate
     * @param keyStoreFileData
     *            certificate data along with its private key
     * @return String name of the KeyStoreFile.
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     * @throws UnrecoverableKeyException
     *             in case key cannot be recovered from KeyStore
     */
    String addCertChainToKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException;

}
