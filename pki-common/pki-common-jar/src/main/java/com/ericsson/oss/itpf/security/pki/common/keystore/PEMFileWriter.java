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

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;

/**
 * This class is used to write the Certificate/s data into PEM file.
 * 
 * @author xpranma
 * 
 */
public class PEMFileWriter implements KeyStoreFileWriter {

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
        logger.debug("Creating keystore for storing certificates");
        Resource resource = null;
        final String pemFilePath = keyStoreInfo.getFilePath();
        resource = Resources.getFileSystemResource(pemFilePath);

        if (resource.exists()) {
            resource.delete();
        }
        createPEMCertificate(certificates, pemFilePath);
        resource.setURI(pemFilePath);

        return resource;

    }

    @Override
    public Resource addCertificateChainToKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {
        return null;
    }

    private String createPEMCertificate(final List<Certificate> certificates, final String pemFilePath) throws IOException {

        Writer writer = null;

        JcaPEMWriter pemWriter = null;

        logger.debug("Creating PEM file.");
        try {

            writer = new FileWriter(pemFilePath, true);
            pemWriter = new JcaPEMWriter(writer);

            for (final Certificate certificate : certificates) {
                pemWriter.writeObject(certificate.getX509Certificate());
            }

        } finally {

            if (pemWriter != null) {
                pemWriter.close();
            }
            if (writer != null) {
                writer.close();
            }
        }
        return fileUtility.getFileNameFromAbsolutePath(pemFilePath);
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
        return createPEMCertificate(certificates, keyStoreInfo.getFilePath());
    }

    @Override
    public String addCertChainToKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {
        return null;
    }
}
