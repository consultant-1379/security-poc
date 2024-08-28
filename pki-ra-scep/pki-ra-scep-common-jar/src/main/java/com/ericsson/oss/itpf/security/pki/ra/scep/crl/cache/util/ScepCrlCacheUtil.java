/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util;

import java.io.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.util.CRLUtility;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidFileExtensionException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pkira.scep.cdt.ScepCrl;

/**
 * This class is used to loadCache with the CRLs provided by CredentialManager. Cache is loaded once,when RA service is Started.
 * 
 * @author xchowja
 *
 */
@ApplicationScoped
public class ScepCrlCacheUtil {

    @Inject
    private ConfigurationListener configurationListener;

    @Inject
    private ScepCrlCacheWrapper scepCrlCacheWrapper;

    @Inject
    Logger logger;

    @Inject
    private CRLUtility crlUtility;

    /**
     * This method is used to load the cache with the available CRLs. CRL Location can be fetched from the configuration parameter.
     * 
     */
    public void initializeCRLCache() {
        String cRLDirectoryPath;
        List<File> cRLFiles;
        logger.info("initialiseCRLCache method in ScepCrlCacheUtil");
        cRLDirectoryPath = configurationListener.getScepCRLPath();
        logger.info("CRL Path is: {}" , cRLDirectoryPath);
        cRLFiles = FileUtility.listFiles(cRLDirectoryPath);
        loadCache(cRLFiles);
        logger.info("CRL cache initialized");

    }

    private X509CRL generateCRLFromFactory(final String cRLfile) throws CertificateException, CRLException {
        logger.info("generateCRLFromFactory method in ScepCrlCacheUtil");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.X509);
        final Resource resource = Resources.getFileSystemResource(cRLfile);
        InputStream is = null;
        X509CRL x509CRL = null;
        try {
            is = resource.getInputStream();
            x509CRL = (X509CRL) certificateFactory.generateCRL(is);
            logger.info("End of generateCRLFromFactory method in ScepCrlCacheUtil");
        } finally {
            Resources.safeClose(is);
        }
        return x509CRL;
    }

    private void loadCache(final List<File> crlFiles) {
        logger.info("loadCache method in ScepCrlCacheUtil");
        String issuerName;
        String cRLAbsolutePath;
        ScepCrl scepCrl;
        X509CRL x509CRL;
        final List<String> extensions = new ArrayList<>();
        extensions.add(Constants.CRL_EXTENSION);
        extensions.add(Constants.PEM_EXTENSION);
        for (final File cRLFile : crlFiles) {
            if (!cRLFile.isDirectory()) {
                cRLAbsolutePath = cRLFile.getAbsolutePath();
                try {
                    FileUtility.verifyFileExtension(cRLAbsolutePath, extensions);
                    x509CRL = generateCRLFromFactory(cRLAbsolutePath);
                    scepCrl = convertToCRLCDT(x509CRL);
                    issuerName = crlUtility.getIssuerCN(x509CRL);
                    scepCrlCacheWrapper.insertOrUpdate(issuerName, scepCrl);
                } catch (InvalidFileExtensionException exception) {
                    logger.warn("Invalid CRL File extension found  while inserting crls into cache.Only files with .crl and .pem extensions are allowed.");
                } catch (CRLException crlException) {
                    logger.error(ErrorMessages.CRL_FORMAT_ERROR + crlException.getMessage());
                } catch (CertificateException certificateException) {
                    logger.error(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND + certificateException.getMessage());
                } catch (CertificateUtilityException certificateUtilityException) {
                    logger.error(ErrorMessages.NO_SUCH_PROVIDER + certificateUtilityException.getMessage());
                } catch (Exception exception) {
                    logger.error("Exception occurred while inserting crls into cache {}", exception.getMessage());
                }
            }
        }
        logger.info("End of loadCache method in ScepCrlCacheUtil");
    }

    private ScepCrl convertToCRLCDT(final X509CRL x509CRL) throws CRLException {
        logger.info("convertToCRLCDT method in ScepCrlCacheUtil");
        final ScepCrl scepCrl = new ScepCrl();
        scepCrl.setCrlEncoded(x509CRL.getEncoded());
        logger.info("End of convertToCRLCDT method in ScepCrlCacheUtil");
        return scepCrl;

    }

    /**
     * This method will update existing CRL cache for modified/new CRL file name. If file already exist in cache, will update with the cache and If new file it will add to cache.
     * 
     * @param modifiedFileName
     *            for which CRL cache will be update.
     */
    public void updateCache(final String modifiedFileName) {
        logger.info("updateCache method in ScepCrlCacheUtil class");
        String issuerName;
        String cRLAbsolutePath;
        ScepCrl scepCrl;
        X509CRL x509CRL;
        final String cRLDirectoryPath = configurationListener.getScepCRLPath();
        final File modifiedCRLFile = new File(cRLDirectoryPath + "/" + modifiedFileName);
        final List<String> extensions = new ArrayList<String>();
        extensions.add(Constants.CRL_EXTENSION);
        extensions.add(Constants.PEM_EXTENSION);
        if (!modifiedCRLFile.isDirectory()) {
            cRLAbsolutePath = modifiedCRLFile.getAbsolutePath();
            try {
                FileUtility.verifyFileExtension(cRLAbsolutePath, extensions);
                x509CRL = generateCRLFromFactory(cRLAbsolutePath);
                scepCrl = convertToCRLCDT(x509CRL);
                issuerName = crlUtility.getIssuerCN(x509CRL);
                scepCrlCacheWrapper.insertOrUpdate(issuerName, scepCrl);
                logger.info("Successfully updated CRL cache for the file {}", modifiedFileName);
            } catch (InvalidFileExtensionException exception) {
                logger.warn("Invalid CRL File extension found while updating crls into cache.Only files with .crl and .pem extensions are allowed.");
            } catch (CRLException crlException) {
                logger.error(ErrorMessages.CRL_FORMAT_ERROR + crlException.getMessage());
            } catch (CertificateException certificateException) {
                logger.error(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND + certificateException.getMessage());
            } catch (CertificateUtilityException certificateUtilityException) {
                logger.error(ErrorMessages.NO_SUCH_PROVIDER + certificateUtilityException.getMessage());
            } catch (Exception exception) {
                logger.error("Exception occurred while updating cache {} ", exception.getMessage());
            }
        }
        logger.info("End of updateCache method in ScepCrlCacheUtil class");
    }

    /**
     * This method is used to fetch the CRL from the loaded cache based on the issuer name provided. if respective cRL is found, then it converts into X509CRL and returns else exception is thrown.
     * 
     * @param issuerName
     *            issuer for which CRL has to be fetched.
     * @return
     * @throws CRLValidationException
     *             This exception will handle certificateException(is thrown if no Provider supports a CertificateFactory implementation for the specified type.) and CRLException(is thrown if any
     *             parsing errors occurs while generating CRL)
     * @throws IOException
     *             is thrown if an I/0 Error occurs while closing ByteArrayInputStream.
     */
    public X509CRL getCRL(final String issuerName) throws CRLValidationException, IOException {
        logger.info("getCRL method of ScepCrlStore class");
        X509CRL x509cRL = null;
        CertificateFactory certificateFactory;
        byte[] cRLEncoded = null;
        ByteArrayInputStream crlInputStream = null;
        try {
            final ScepCrl scepCrl = scepCrlCacheWrapper.get(issuerName);
            if (scepCrl != null) {
                cRLEncoded = scepCrl.getCrlEncoded();
                crlInputStream = new ByteArrayInputStream(cRLEncoded);
                certificateFactory = CertificateFactory.getInstance(Constants.X509);
                x509cRL = (X509CRL) certificateFactory.generateCRL(crlInputStream);
            } else {
                logger.error("CRL File is not found in the cache of ScepCrlStore class");
            }
        } catch (CertificateException certificateException) {
            logger.error("Exception since  no Provider supports a CertificateFactory implementation for the specified type of ScepCrlStore class");
            throw new CRLValidationException(ErrorMessages.CERTIFICATE_TYPE_NOT_SUPPORTED_BY_THE_PROVIDER, certificateException);

        } catch (CRLException crlException) {
            logger.error("Exception thrown since data in the input stream does not contain an inherent end-of-CRL marker (other than EOF) and there is trailing data after the CRL is parsed, a CRLException is thrown of ScepCrlStore class");
            throw new CRLValidationException(ErrorMessages.CRL_FORMAT_ERROR, crlException);

        } finally {
            if (crlInputStream != null) {
                crlInputStream.close();
            }
        }
        logger.info("End of getCRL method of ScepCrlStore class");
        return x509cRL;
    }
}
