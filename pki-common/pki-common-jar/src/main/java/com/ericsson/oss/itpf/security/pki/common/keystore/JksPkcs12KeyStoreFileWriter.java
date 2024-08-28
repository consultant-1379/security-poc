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

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;

/**
 * This class is used to write/add the Certificate/s data into JKS/PKCS12 KeyStore based on input.
 * 
 * @author xpranma
 * 
 */
public class JksPkcs12KeyStoreFileWriter implements KeyStoreFileWriter {

    @Inject
    KeyStoreFileWriterHelper keyStoreFileWriterHelper;

    @Inject
    FileUtility fileUtility;

    @Inject
    Logger logger;

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
    @Override
    public Resource createCertificateKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {
        createCertKeyStore(certificates, keyStoreInfo);
        return Resources.getFileSystemResource(keyStoreInfo.getFilePath());

    }

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
     *             in case key and cannot be recovered from keystore
     */
    @Override
    public Resource addCertificateChainToKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {
        addCertChainToKeyStore(certificates, keyStoreInfo, keyStoreFileData);
        return Resources.getFileSystemResource(keyStoreInfo.getFilePath());

    }

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
    @Override
    public String createCertKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException,
            NoSuchProviderException {
        logger.debug("Creating keystore for storing certificates in it");
        FileOutputStream fos = null;
        String password = "";

        try {
            if (keyStoreInfo.getPassword() != null) {
                password = keyStoreInfo.getPassword();
            }
            keyStoreInfo.setPassword(password);

            final KeyStore keyStore = keyStoreFileWriterHelper.loadKeyStoreWithData(keyStoreInfo, null);
            if (certificates.size() == 1) {
                keyStore.setCertificateEntry(keyStoreInfo.getAliasName(), certificates.get(0).getX509Certificate());
            } else {
                int count = 1;
                for (final Certificate certificate : certificates) {
                    keyStore.setCertificateEntry(keyStoreInfo.getAliasName() + "_" + count, certificate.getX509Certificate());
                    count++;
                }
            }

            fos = new FileOutputStream(keyStoreInfo.getFilePath());

            keyStore.store(fos, password.toCharArray());
            return fileUtility.getFileNameFromAbsolutePath(keyStoreInfo.getFilePath());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }

    }

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
    @Override
    public String addCertChainToKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {
        logger.debug("Adding certificate chain into keystore");
        FileOutputStream out = null;
        String password = "";

        try {

            if (keyStoreInfo.getPassword() != null) {
                password = keyStoreInfo.getPassword();
            }

            out = new FileOutputStream(keyStoreInfo.getFilePath());
            final KeyStore keyStore = keyStoreFileWriterHelper.loadKeyStoreWithData(keyStoreInfo, keyStoreFileData);
            final Key privateKey = keyStore.getKey(keyStoreInfo.getAliasName(), password.toCharArray());
            if (privateKey != null) {
                keyStore.deleteEntry(keyStoreInfo.getAliasName());
                final X509Certificate[] x509certificateChain = createCertificateArray(certificates);
                keyStore.setKeyEntry(keyStoreInfo.getAliasName(), privateKey, password.toCharArray(), x509certificateChain);
            } else {
                int count = 1;
                for (final Certificate certificate : certificates) {
                    keyStore.setCertificateEntry(keyStoreInfo.getAliasName() + "_" + count, certificate.getX509Certificate());
                    count++;
                }
            }
            keyStore.store(out, password.toCharArray());

            return fileUtility.getFileNameFromAbsolutePath(keyStoreInfo.getFilePath());

        } finally {
            if (out != null) {
                out.close();
            }
        }

    }

    /**
     * Method that returns certificate array when list of certificates are passed
     * 
     * @param certificates
     *            list of certificates
     * @return x509certificateArray
     * @throws CertificateException
     *             indicates one of certificate problems
     */
    private X509Certificate[] createCertificateArray(final List<Certificate> certificates) throws CertificateException {

        X509Certificate[] x509certificateArray = null;

        if (certificates == null) {
            logger.error("Error occured due to empty certificate list");
            throw new CertificateException();
        }

        final ArrayList<X509Certificate> x509certificateList = new ArrayList<>();
        x509certificateArray = new X509Certificate[certificates.size()];

        for (final Certificate certificate : certificates) {
            x509certificateList.add(certificate.getX509Certificate());
        }

        x509certificateArray = x509certificateList.toArray(x509certificateArray);
        return x509certificateArray;

    }

}
