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

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.*;

import javax.cache.Cache;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidFileExtensionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CRL;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.CRLCacheWrapper;

@RunWith(MockitoJUnitRunner.class)
public class CRLCacheUtilTest {
    @InjectMocks
    CRLCacheUtil crlCacheUtil;

    @Mock
    @NamedCache("CRLCache")
    Cache<String, CRL> cRLCache;

    @Mock
    Logger logger;

    @Mock
    CertificateFactory certificateFactory;

    @Mock
    ConfigurationParamsListener configurationListener;

    @Mock
    CRLCacheWrapper crlCacheWrapper;

    final String cRLPath = CRLCacheUtil.class.getResource("/Crls").getPath();
    final String cRLFile = "VC_CB4_SubCA_A1_1_1.crl";
    final String invalidCRLFile = "InvalidFile.txt";

    @Test
    public void testInitialiseCRLCache() {
        Mockito.when(configurationListener.getCRLPath()).thenReturn(cRLPath);
        crlCacheUtil.initialiseCRLCache();
        Mockito.verify(configurationListener).getCRLPath();

    }

    @Test
    public void testUpdateCache() throws CertificateException, CRLException, NoSuchProviderException, IOException {
        Mockito.when(configurationListener.getCRLPath()).thenReturn(cRLPath);
        crlCacheUtil.updateCache(cRLFile);
        Mockito.verify(configurationListener).getCRLPath();
    }

    @Test
    public void testInvalidFileExtensionException()
            throws CertificateException, CRLException, NoSuchProviderException, CertificateUtilityException, IOException {
        Mockito.when(configurationListener.getCRLPath()).thenReturn(cRLPath);
        try {
            crlCacheUtil.updateCache(invalidCRLFile);
        } catch (final InvalidFileExtensionException exception) {
            Assert.assertTrue(exception.getMessage().contains("Invalid file extension found while updating CRL Cache"));
        }
    }

    @Test
    public void testUpdateCacheInvalidFileExtensionException() throws CertificateException, CRLException, NoSuchProviderException, IOException {
        Mockito.when(configurationListener.getCRLPath()).thenReturn(cRLPath);
        crlCacheUtil.updateCache(cRLFile);
        Mockito.verify(configurationListener).getCRLPath();
    }

}
