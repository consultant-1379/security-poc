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
package com.ericsson.itpf.security.pki.cmdhandler.util;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * Utility for handling Certificate operations
 *
 * @author xsrirko
 *
 */
public class CertificateUtils {

    @Inject
    KeyUtil keyUtil;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    /**
     * Method for Creating File Resource
     *
     * @param certificateInBytes
     * @param fileName
     * @param fileExtension
     * @return filePath
     */
    public String createFileResource(final byte[] certificateInBytes, final String fileName, final String fileExtension) {
        final String filePath = CliUtil.getTempFile(fileName, fileExtension);
        pkiWebCliResourceLocalService.write(filePath, certificateInBytes, false);
        return filePath;
    }

    /**
     * Method for Creating PEM Certificate
     *
     * @param certificates
     * @param fileName
     * @return pem file path
     * @throws IOException
     */
    public String createPEMCertificate(final List<Certificate> certificates, final String fileName) throws IOException {

        final String pemFilePath = CliUtil.getTempFile(fileName, Constants.PEM_EXTENSION);
        Writer writer = null;
        JcaPEMWriter pemWriter = null;
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

        return pemFilePath;
    }

    /**
     * Method for generating PEM File
     *
     * @param pemObject
     * @param fileName
     * @return pem file path
     * @throws IOException
     */
    public String generatePemFile(final PemObject pemObject, final String fileName) throws IOException {

        final String pemFilePath = CliUtil.getTempFile(fileName, Constants.PEM_EXTENSION);
        Writer writer = null;
        JcaPEMWriter pemWriter = null;
        try {
            writer = new FileWriter(pemFilePath, true);
            pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(pemObject);

        } finally {

            if (pemWriter != null) {
                pemWriter.close();
            }
            if (writer != null) {
                writer.close();
            }
        }

        return pemFilePath;
    }

    /**
     * Method for getting Certificate ContentType
     *
     * @param certFileName
     * @return contentType
     */
    public String getContentType(final String certFileName) {
        final Map<String, String> Content_Type_Map = new HashMap<>();
        Content_Type_Map.put(Constants.JKS_EXTENSION, Constants.JKS_CONTENT_TYPE);
        Content_Type_Map.put(Constants.P12_EXTENSION, Constants.P12_CONTENT_TYPE);
        Content_Type_Map.put(Constants.PEM_EXTENSION, Constants.PEM_CONTENT_TYPE);
        Content_Type_Map.put(Constants.DER_EXTENSION, Constants.DER_CONTENT_TYPE);

        return Content_Type_Map.get(certFileName.substring(certFileName.lastIndexOf('.')));
    }

    /**
     * Method for Converting Certificate List to specific format
     *
     * @param certificates
     * @param format
     * @param fileName
     * @param password
     * @return filePath
     * @throws CertificateException
     *             in case of error occurs while attempting to encode a certificate.
     * @throws CommandSyntaxException
     *             when Password is Provided for PEM Certificate
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws IllegalArgumentException
     *             thrown if certificate format is not supported.
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     */
    public String convertCertificates(final List<Certificate> certificates, final String format, final String fileName, final String password) throws CertificateException, CommandSyntaxException,
            KeyStoreException, IllegalArgumentException, IOException, NoSuchProviderException, NoSuchAlgorithmException {

        String filePath = null;

        switch (format) {

        case Constants.JKS_FORMAT:
            filePath = keyUtil.createCertificateKeyStore(certificates, new KeyStoreInfo(CliUtil.getTempFile(fileName, Constants.JKS_EXTENSION), KeyStoreType.JKS, password, Constants.KEYSTORE_ALIAS));
            break;

        case Constants.P12_FORMAT:
            filePath = keyUtil.createCertificateKeyStore(certificates,
                    new KeyStoreInfo(CliUtil.getTempFile(fileName, Constants.P12_EXTENSION), KeyStoreType.PKCS12, password, Constants.KEYSTORE_ALIAS));
            break;

        case Constants.PEM_FORMAT:
            filePath = generatePEMCertificateFile(certificates, fileName, password);
            break;

        case Constants.DER_FORMAT:
            filePath = createFileResource(certificates.get(0).getX509Certificate().getEncoded(), fileName, Constants.DER_EXTENSION);
            break;

        default:
            throw new IllegalArgumentException(PkiErrorCodes.FORMAT_NOT_SUPPORTED);
        }

        return filePath;
    }

    /**
     *
     *
     * @param certificates
     * @param fileName
     * @param password
     * @return
     * @throws CertificateEncodingException
     *             thrown in case of error occurs while attempting to encode a certificate.
     * @throws CommandSyntaxException
     *             when Password is Provided for PEM Certificate
     * @throws IOException
     *             thrown incase of i/o failure
     */
    private String generatePEMCertificateFile(final List<Certificate> certificates, final String fileName, final String password) throws CertificateEncodingException, CommandSyntaxException,
            IOException {

        if (!password.equals(Constants.EMPTY_STRING)) {
            throw new CommandSyntaxException("PEM does not require Password");
        }

        return createPEMCertificate(certificates, fileName);
    }

    /**
     * To get the single PEM file for all the given certificates. It is mostly used for getting certificate chain in a single PEM file.
     * @param certificates
     *            certificates list
     * @param fileName
     *            name of the PEM file
     * @return PEM file
     * @throws IOException
     *             thrown incase of i/o failure
     */
    public File createPEMCertificateFile(final List<Certificate> certificates, final String fileName) throws IOException {
        final String filePath = createPEMCertificate(certificates, fileName);
        return new File(filePath);
    }

    /**
     * To get the separate PEM files for each certificate in the given certificate list
     * @param certificates
     *            certificates list
     * @param fileNameIdentifier
     *            the string to be prepended for certificate PEM file name.
     * @return file array of certificates
     * @throws CertificateException
     *             in case of error occurs while attempting to encode a certificate.
     * @throws IOException
     *             thrown incase of i/o failure
     */
    public File[] createPEMCertificateFiles(final List<Certificate> certificates, final String fileNameIdentifier) throws CertificateException,
            IOException {

        final File[] files = new File[certificates.size() + 1];

        for (int i = 0; i < certificates.size(); i++) {
            final Certificate certificate = certificates.get(i);
            final String fileName = fileNameIdentifier + getCNFromCertificate(certificate);
            final File file = createPEMCertificateFile(Arrays.asList(certificate), fileName);
            files[i] = file;
        }
        return files;
    }

    /**
     * To get Common Name from given certificate
     *
     * @param certificate
     *         the certificate
     * @return CN of certificate
     * @throws CertificateException
     *            in case of error occurs while attempting to encode a certificate.
     */
    public String getCNFromCertificate(final Certificate certificate) throws CertificateException {

        try {
            final X509Certificate cert = certificate.getX509Certificate();

            final X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
            final RDN cn = x500name.getRDNs(BCStyle.CN)[0];

            return cn.getFirst().getValue().toString();
        } catch (CertificateEncodingException certificateEncodingException) {
            throw new CertificateException("Error while encoding certificate", certificateEncodingException);
        }
    }
}
