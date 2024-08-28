/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util;

import static org.junit.Assert.*;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.*;

import javax.cache.Cache;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.util.CRLUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidFileExtensionException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pkira.scep.cdt.ScepCrl;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
public class ScepCrlCacheUtilTest {
    @InjectMocks
    ScepCrlCacheUtil scepCrlCacheUtil;

    @Mock
    @NamedCache("CRLCache")
    Cache<String, ScepCrl> scepCrlCache;

    @Mock
    Logger logger;

    @Mock
    CertificateFactory certificateFactory;

    @Mock
    ConfigurationListener configurationListener;
    @Mock
    ScepCrl scepCrl;
    @Mock
    ByteArrayInputStream byteArrayInputStream;

    @Mock
    Resource resource;

    @Mock
    CRLUtility crlUtility;

    @Mock
    ScepCrlCacheWrapper scepCrlCacheWrapper;

    private static X509CRL x509CRL = null;
    final private String cRLFolder = "/Crls";
    final private String cRLFilePath = "/Crls/SCEPCRL_ENM_Management_CA.crl";
    final private String issuerName = "rootCA";
    final private String cRLPath = ScepCrlCacheUtil.class.getResource(cRLFolder).getPath();
    final private String cRLFile = "SCEPCRL_ENM_Management_CA.crl";
    final private String cAName = "ENM_Management_CA";
    final private String cRLLoggerInfo = "End of getCRL method of ScepCrlStore class";
    final private static String x509 = "x.509";
    final private String cRLFileInvalid = "InvalidFile.txt";
    final private String invalidFileErrorMessage = "Invalid File extension while updating crls into cache :";
    final private String testCRLFile = "test.crl";

    @Test(expected = FileNotFoundException.class)
    public void testInitialiseCRLCache_NoCRLFile_ThrowsFileNotFoundException() {
        Mockito.when(configurationListener.getScepCRLPath()).thenReturn(cRLPath);
        Mockito.when(configurationListener.getScepCRLPath()).thenThrow(FileNotFoundException.class);

        scepCrlCacheUtil.initializeCRLCache();
        Mockito.verify(configurationListener).getScepCRLPath();

    }

    @Test
    public void testInitialiseCRLCache() {
        mockResource();
        scepCrlCacheUtil.initializeCRLCache();
        Mockito.verify(configurationListener).getScepCRLPath();

    }

    @Test
    public void testInitialiseCRLCache_InvalidCertificateFactory_ThrowsCertificateException() {
        mockResource();
        Mockito.doThrow(CertificateException.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());
        scepCrlCacheUtil.initializeCRLCache();
        Mockito.verify(configurationListener).getScepCRLPath();

    }

    @Test
    public void testInitialiseCRLCache_InvalidCertificateFactory_ThrowsInvalidFileException() {
        mockResource();
        Mockito.doThrow(InvalidFileExtensionException.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());
        scepCrlCacheUtil.initializeCRLCache();
        Mockito.verify(configurationListener).getScepCRLPath();

    }

    @Test
    public void testInitialiseCRLCache_BouncyCastleProviderNotPresent_ThrowsCertificateUtilityException() {
        mockResource();
        Mockito.doThrow(CertificateUtilityException.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());
        scepCrlCacheUtil.initializeCRLCache();
        Mockito.verify(configurationListener).getScepCRLPath();

    }

    @Test
    public void testInitialiseCRLCache_InsertingCrlsIntoCache_ThrowsException() {
        mockResource();
        Mockito.doThrow(Exception.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());
        scepCrlCacheUtil.initializeCRLCache();
        Mockito.verify(configurationListener).getScepCRLPath();

    }

    @Test
    public void testUpdateCache() {
        mockResource();
        scepCrlCacheUtil.updateCache(cRLFile);
        Mockito.verify(configurationListener).getScepCRLPath();
    }

    @Test
    public void testUpdateCache_ContainsKey_UpdatesCache() {
        mockResource();
        Mockito.when(scepCrlCache.containsKey(cAName)).thenReturn(true);

        scepCrlCacheUtil.updateCache(cRLFile);
        Mockito.verify(configurationListener).getScepCRLPath();
    }

    @Test
    public void testGetCRL() {
        try {
            scepCrlCache = getCRL();
            Mockito.when(scepCrlCache.get(issuerName)).thenReturn(scepCrl);
            Mockito.when(scepCrl.getCrlEncoded()).thenReturn(x509CRL.getEncoded());
            final String cRLAbsolutePath = ScepCrlCacheUtil.class.getResource(cRLFilePath).getPath();
            x509CRL = generateCRLFromFactory(cRLAbsolutePath);
            scepCrl.setCrlEncoded(x509CRL.getEncoded());
            Mockito.when(scepCrlCacheWrapper.get(issuerName)).thenReturn(scepCrl);

            X509CRL x509crl = scepCrlCacheUtil.getCRL(issuerName);

            assertNotNull(x509crl);
            assertTrue(x509crl.getIssuerDN().toString().contains(cAName));

            Mockito.verify(scepCrlCacheWrapper).get(issuerName);
            Mockito.verify(logger).info(cRLLoggerInfo);
        } catch (CRLValidationException | IOException | CRLException | CertificateException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetCRL_CRLNotFound_ReturnsNull() {
        try {

            scepCrlCache = getCRL();
            Mockito.when(scepCrlCache.get(issuerName)).thenReturn(null);
            Mockito.when(scepCrl.getCrlEncoded()).thenReturn(x509CRL.getEncoded());
            X509CRL x509crl = scepCrlCacheUtil.getCRL(issuerName);
            assertNull(x509crl);
            Mockito.verify(scepCrlCacheWrapper).get(issuerName);
        } catch (CRLValidationException | IOException | CRLException | CertificateException e) {
            fail(e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetCRL_CertificateTypeNotSupported_ThrowsCertificateException() {
        try {

            scepCrlCache = getCRL();
            Mockito.when(scepCrlCache.get(issuerName)).thenReturn(scepCrl);
            Mockito.when(scepCrl.getCrlEncoded()).thenThrow(CertificateException.class);
            Mockito.when(scepCrlCacheWrapper.get(issuerName)).thenReturn(scepCrl);

            scepCrlCacheUtil.getCRL(issuerName);
            Mockito.verify(scepCrlCache).get(issuerName);
            Mockito.verify(scepCrl).getCrlEncoded();
        } catch (CRLValidationException | IOException | CRLException | CertificateException e) {
            assertTrue(e.getMessage().contains(ErrorMessages.CERTIFICATE_TYPE_NOT_SUPPORTED_BY_THE_PROVIDER));
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetCRL_ImproperCRLFormat_ThrowsCRLValidationException() {
        try {
            scepCrlCache = getCRL();
            Mockito.when(scepCrlCache.get(issuerName)).thenReturn(scepCrl);
            Mockito.when(scepCrl.getCrlEncoded()).thenThrow(CRLException.class);

            final String cRLAbsolutePath = ScepCrlCacheUtil.class.getResource(cRLFilePath).getPath();
            x509CRL = generateCRLFromFactory(cRLAbsolutePath);
            scepCrl.setCrlEncoded(x509CRL.getEncoded());
            Mockito.when(scepCrlCacheWrapper.get(issuerName)).thenReturn(scepCrl);

            scepCrlCacheUtil.getCRL(issuerName);
            Mockito.verify(scepCrlCache).get(issuerName);
            Mockito.verify(scepCrl).getCrlEncoded();
        } catch (CRLValidationException | IOException | CRLException | CertificateException e) {
            assertTrue(e.getMessage().contains(ErrorMessages.CRL_FORMAT_ERROR));
        }
    }

    private Cache<String, ScepCrl> getCRL() throws CRLException, CertificateException, FileNotFoundException {
        final String cRLAbsolutePath = ScepCrlCacheUtil.class.getResource(cRLFilePath).getPath();
        x509CRL = generateCRLFromFactory(cRLAbsolutePath);
        scepCrl.setCrlEncoded(x509CRL.getEncoded());
        scepCrlCache.put(cRLFile, scepCrl);
        return scepCrlCache;
    }

    private X509CRL generateCRLFromFactory(final String cRLfile) throws CertificateException, FileNotFoundException, CRLException {
        X509CRL x509CRL;
        CertificateFactory certificateFactory;
        certificateFactory = CertificateFactory.getInstance(x509);
        final FileInputStream fileinputstream = new FileInputStream(cRLfile);
        x509CRL = (X509CRL) certificateFactory.generateCRL(fileinputstream);
        return x509CRL;
    }

    private static X509CRL getCRL(final String filename) throws IOException, CertificateException, CRLException {
        final FileInputStream fin = new FileInputStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(x509);
        final X509CRL cRL = (X509CRL) certificateFactory.generateCRL(fin);
        return cRL;
    }

    private void mockResource() {
        Mockito.when(configurationListener.getScepCRLPath()).thenReturn(cRLPath);
        final URL url = Thread.currentThread().getContextClassLoader().getResource(cRLFile);
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        try {
            x509CRL = getCRL(filename);
        } catch (CertificateException | CRLException | IOException e) {
            fail(e.getMessage());
        }
        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(Resources.getFileSystemResource(Matchers.anyString())).thenReturn((resource));

        final String issuerName = ScepCrlCacheUtil.class.getResource(cRLFolder).getPath();
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(cRLFile);
        Mockito.when(resource.getInputStream()).thenReturn((is));
        try {
            Mockito.when((X509CRL) certificateFactory.generateCRL((InputStream) Mockito.any())).thenReturn(x509CRL);
        } catch (CRLException e) {
            fail(e.getMessage());
        }
        Mockito.when(crlUtility.getIssuerCN(x509CRL)).thenReturn(issuerName);
    }

    @Test
    public void testupdateCache_InvalidFileExtention_ThrowsInvalidFileExtensionException() {

        Mockito.when(configurationListener.getScepCRLPath()).thenReturn(cRLPath);
        try {
            scepCrlCacheUtil.updateCache(cRLFileInvalid);
        } catch (InvalidFileExtensionException exception) {
            assertTrue(exception.getMessage().contains(invalidFileErrorMessage));
        }
    }

    @Test
    public void testUpdateCache_InvalidCRL_ThrowsException() {

        Mockito.when(configurationListener.getScepCRLPath()).thenReturn(cRLPath);

        scepCrlCacheUtil.updateCache(testCRLFile);

        Mockito.verify(logger).error(Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void testUpdateCache_InvalidCRL_ThrowsCRLException() {

        mockResource();

        Mockito.doThrow(CRLException.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());

        scepCrlCacheUtil.updateCache(cRLFile);

        Mockito.verify(logger).error(Mockito.anyString());

    }

    @Test
    public void testUpdateCache_InvalidCertificate_CertificateException() {

        mockResource();

        Mockito.doThrow(CertificateException.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());

        scepCrlCacheUtil.updateCache(cRLFile);

        Mockito.verify(logger).error(Mockito.anyString());

    }

    @Test
    public void testUpdateCache_InvalidCertificate_ThrowsCertificateUtilityException() {

        mockResource();

        Mockito.doThrow(CertificateUtilityException.class).when(scepCrlCacheWrapper).insertOrUpdate(Mockito.anyString(), (ScepCrl) Mockito.any());

        scepCrlCacheUtil.updateCache(cRLFile);

        Mockito.verify(logger).error(Mockito.anyString());

    }

}