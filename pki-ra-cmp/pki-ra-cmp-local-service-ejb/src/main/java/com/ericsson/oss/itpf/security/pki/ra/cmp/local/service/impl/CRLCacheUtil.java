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

package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import java.io.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidFileExtensionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.CRLCacheException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CRL;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.CRLCacheWrapper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.CRLStore;

/**
 * This class is used to loadCache with the CRLs provided by CredentialManager. Cache is loaded once,when RA service is Started.
 *
 * @author tcsramc
 */
@ApplicationScoped
public class CRLCacheUtil {

    @Inject
    CRLCacheWrapper cRLCacheWrapper;

    @Inject
    ConfigurationParamsListener configurationListener;

    @Inject
    Logger logger;

    @Inject
    CRLStore cRLStore;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * This method is used to load the cache with the available CRLs. CRL Location can be fetched from the configuration parameter.
     *
     * @throws CRLCacheException
     *             is thrown if CRL file is not found in the given location or if any parsing error occurs while generating CRLs.
     */
    public void initialiseCRLCache() {
        String cRLDirectoryPath;
        List<File> cRLFiles;
        logger.info("initialiseCRLCache method in CRLCacheUtil");
        cRLDirectoryPath = configurationListener.getCRLPath();
        logger.info("CRL Path is: {}" , cRLDirectoryPath);
        cRLFiles = FileUtility.listFiles(cRLDirectoryPath);
        loadCache(cRLFiles);
        logger.info("CRL cache initialized");

    }

    /**
     * This method is used to update the cache (based on the caname provided as an argument) when a new CRL is added in the given path
     *
     * @param caName
     *            caName - for which CRL has to be fetched.
     * @return
     * @throws CRLCacheException
     *             is thrown if CRL file is not found in the given location or if any parsing error occurs while generating CRLs or unsupported
     *             Provider found.
     */

    private X509CRL generateCRLFromFactory(final String cRLfile) throws CertificateException, CRLException, FileNotFoundException, IOException {
        logger.info("generateCRLFromFactory method in CRLCacheUtil");
        X509CRL x509CRL;
        CertificateFactory certificateFactory;
        FileInputStream fileinputstream = null;
        try {
            certificateFactory = CertificateFactory.getInstance(Constants.X509);
            fileinputstream = new FileInputStream(cRLfile);
            x509CRL = (X509CRL) certificateFactory.generateCRL(fileinputstream);
        } finally {
            if (fileinputstream != null) {
                fileinputstream.close();
            }
        }
        logger.info("End of generateCRLFromFactory method in CRLCacheUtil");
        return x509CRL;
    }

    private void loadCache(final List<File> crlFiles) {
        logger.info("loadCache method in CRLCacheUtil");
        String issuerName;
        String cRLAbsolutePath;
        CRL cRL;
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
                    cRL = convertToCRLCDT(x509CRL);
                    issuerName = getIssuerCN(x509CRL);
                    cRLCacheWrapper.insertOrUpdate(issuerName, cRL);
                } catch (final InvalidFileExtensionException invalidFileExtensionException) {
                    logger.warn("Invalid CRL File extension found while loading crls into cache.Only files with .crl and .pem extensions are allowed", invalidFileExtensionException);
                    continue;

                } catch (final FileNotFoundException fileNotFoundException) {
                    logger.error(ErrorMessages.FILE_NOT_FOUND_IN_PATH, fileNotFoundException);
                    systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.FILE_NOT_FOUND_IN_PATH, "PKIRACMPService.CRLFileVerification",
                            ErrorSeverity.CRITICAL, "FAILURE");
                    continue;

                } catch (final CRLException crlException) {
                    logger.error(ErrorMessages.CRL_FORMAT_ERROR, crlException);
                    systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.CRL_FORMAT_ERROR, "PKIRACMPService.CRLFileVerification", ErrorSeverity.CRITICAL,
                            "FAILURE");
                    continue;

                } catch (final CertificateException certificateException) {
                    logger.error(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND, certificateException);
                    systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND, "PKIRACMPService.CRLFileVerification",
                            ErrorSeverity.CRITICAL, "FAILURE");
                    continue;

                } catch (final CertificateUtilityException certificateUtilityException) {
                    logger.error(ErrorMessages.INVALID_CERTIFICATE, certificateUtilityException);
                    systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.INVALID_CERTIFICATE, "PKIRACMPService.CRLFileVerification",
                            ErrorSeverity.CRITICAL, "FAILURE");
                    continue;

                } catch (final IOException iOException) {
                    logger.error(ErrorMessages.IO_EXCEPTION, iOException);
                    systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.IO_EXCEPTION, "PKIRACMPService.CRLFileVerification", ErrorSeverity.CRITICAL,
                            "FAILURE");
                    continue;
                } catch (final Exception exception) {
                    logger.error("Exception occurred while loading cache{} ", exception.getMessage());
                    logger.debug("Exception occurred while loading cache ", exception);
                    continue;
                }
            }
        }
        logger.info("End of loadCache method in CRLCacheUtil");
    }

    private CRL convertToCRLCDT(final X509CRL x509CRL) throws CRLException {
        logger.info("convertToCRLCDT method in CRLCacheUtil");
        final CRL cRL = new CRL();
        cRL.setCrlEncoded(x509CRL.getEncoded());
        logger.info("End of convertToCRLCDT method in CRLCacheUtil");
        return cRL;

    }

    private String getIssuerCN(final X509CRL x509CRL) throws CertificateUtilityException {
        logger.info("getIssuerCN method in CRLCacheUtil");
        String issuerName;
        final X500Principal principal = x509CRL.getIssuerX500Principal();
        final X500Name x500name = new X500Name(principal.getName());
        final RDN commonName = x500name.getRDNs(BCStyle.CN)[0];
        issuerName = IETFUtils.valueToString(commonName.getFirst().getValue());
        logger.info("End of getIssuerCN method in CRLCacheUtil");
        return issuerName;

    }

    /**
     * Will update existing CRL cache for modified/new CRL file name. If file already exist in cache, will update with the cache and If new file it
     * will add to cache.
     *
     * @param modifiedFileName
     *            for which CRL cache will be update.
     */
    public void updateCache(final String modifiedFileName) {
        String issuerName;
        String cRLAbsolutePath;
        CRL cRL;
        X509CRL x509CRL;
        final String cRLDirectoryPath = configurationListener.getCRLPath();
        final File modifiedCRLFile = new File(cRLDirectoryPath + "/" + modifiedFileName);
        final List<String> extensions = new ArrayList<>();
        extensions.add(Constants.CRL_EXTENSION);
        extensions.add(Constants.PEM_EXTENSION);
        if (!modifiedCRLFile.isDirectory()) {
            cRLAbsolutePath = modifiedCRLFile.getAbsolutePath();
            try {
                FileUtility.verifyFileExtension(cRLAbsolutePath, extensions);

                x509CRL = generateCRLFromFactory(cRLAbsolutePath);
                cRL = convertToCRLCDT(x509CRL);
                issuerName = getIssuerCN(x509CRL);
                cRLCacheWrapper.insertOrUpdate(issuerName, cRL);
            } catch (final InvalidFileExtensionException invalidFileExtensionException) {
                logger.warn("Invalid CRL File extension found while updating crls into cache.Only files with .crl and .pem extensions are allowed ", invalidFileExtensionException);

            } catch (final FileNotFoundException fileNotFoundException) {
                logger.error(ErrorMessages.FILE_NOT_FOUND_IN_PATH, fileNotFoundException);
                systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.FILE_NOT_FOUND_IN_PATH, "PKIRACMPService.CRLFileVerification",
                        ErrorSeverity.CRITICAL, "FAILURE");
            } catch (final CRLException crlException) {
                logger.error(ErrorMessages.CRL_FORMAT_ERROR, crlException);
                systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.CRL_FORMAT_ERROR, "PKIRACMPService.CRLFileVerification", ErrorSeverity.CRITICAL,
                        "FAILURE");
            } catch (final CertificateException certificateException) {
                logger.error(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND, certificateException);
                systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND, "PKIRACMPService.CRLFileVerification",
                        ErrorSeverity.CRITICAL, "FAILURE");
            } catch (final CertificateUtilityException certificateUtilityException) {
                logger.error(ErrorMessages.INVALID_CERTIFICATE, certificateUtilityException);
                systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.INVALID_CERTIFICATE, "PKIRACMPService.CRLFileVerification", ErrorSeverity.CRITICAL,
                        "FAILURE");
            } catch (final IOException iOException) {
                logger.error(ErrorMessages.IO_EXCEPTION, iOException);
                systemRecorder.recordSecurityEvent("PKIRACMPService", "PKIRACMPService.CRLVerifier", ErrorMessages.IO_EXCEPTION, "PKIRACMPService.CRLFileVerification", ErrorSeverity.CRITICAL,
                        "FAILURE");
            } catch (final Exception exception) {
                logger.error("Exception occurred while loading cache{} ", exception.getMessage());
                logger.debug("Exception occurred while loading cache ", exception);
            }
        }
    }
}
