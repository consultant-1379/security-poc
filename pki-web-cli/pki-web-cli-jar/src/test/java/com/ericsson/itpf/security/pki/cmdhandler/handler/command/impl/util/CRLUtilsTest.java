/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.BaseTest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRL;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;

/**
 * Test Class for checking Unit test for CRLUtils Class.
 * 
 * 
 */

@RunWith(MockitoJUnitRunner.class)
public class CRLUtilsTest {
    @InjectMocks
    CRLUtils cRLUtils;

    CRLStatus cRLStatus;

    @Mock
    CRLNumber crlNumber;

    @Mock
    Logger logger;

    @Mock
    Certificate certificate;

    @Mock
    X509Certificate x509Certificate;

    List<CRLInfo> cRLInfoList = new ArrayList<CRLInfo>();
    CRLInfo cRLInfo = new CRLInfo();
    CRL cRL = new CRL();
    String filename;

    @Before
    public void setUp() throws Exception {
        final URL url = Thread.currentThread().getContextClassLoader().getResource("testCA.crl");
        filename = url.getFile();
        filename = URLDecoder.decode(filename);
        final X509CRL x509CRL = BaseTest.getCRL(filename);
        final X509CRLHolder x509crlHolder = new X509CRLHolder(x509CRL.getEncoded());
        cRL.setX509CRLHolder(x509crlHolder);
        cRLInfo.setCrl(cRL);
        cRLInfo.setId(1);
        cRLInfoList.add(cRLInfo);
        cRLInfo.setCrlNumber(crlNumber);
        cRLInfo.setIssuerCertificate(certificate);

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CRLUtils}
     * 
     * @throws IOException
     * 
     */

    @Ignore
    @Test
    public void testCreateCRLFiles() throws IOException, CertificateException, CRLException {
        Mockito.when(cRLInfo.getIssuerCertificate().getSerialNumber()).thenReturn("12345");
        final String cAName = "CANAME";
        final File[] file = cRLUtils.createCRLFiles(cRLInfoList, cAName);
        assertNotNull(file);
    }

    @Ignore
    @Test
    public void testCreateZipFile() throws IOException {
        final String cAName = "CANAME";
        final File[] files = cRLUtils.createCRLFiles(cRLInfoList, cAName);
        final File file = cRLUtils.createZipFile(files, "zipFile");
        assertNotNull(file);
    }

    @Test
    public void testConvertFiletoByteArray() throws IOException {
        final File file = new File(filename);
        final byte[] bytes = cRLUtils.convertFiletoByteArray(file);
        assertNotNull(bytes);

    }

}
