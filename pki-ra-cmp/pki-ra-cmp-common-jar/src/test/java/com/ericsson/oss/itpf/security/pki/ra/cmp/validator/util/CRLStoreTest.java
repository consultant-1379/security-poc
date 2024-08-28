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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util;

import java.io.*;
import java.security.cert.*;

import javax.cache.Cache;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CRL;

@RunWith(MockitoJUnitRunner.class)
public class CRLStoreTest {
    @InjectMocks
    CRLStore cRLStore;

    @Mock
    @NamedCache("CRLCache")
    private Cache<String, CRL> cRLCache;

    @Mock
    CRL cRLModel;

    @Mock
    Logger logger;
    
    @Mock
    CRLCacheWrapper crlCacheWrapper;

    private static X509CRL x509CRL = null;

    @Test
    public void testGetCRL() throws CRLValidationException, IOException, CRLException, CertificateException {
        final String issuerName = CRLStore.class.getResource("/Crls").getPath();
        cRLCache = getCRL();
        Mockito.when(crlCacheWrapper.get(issuerName)).thenReturn(cRLModel);
        Mockito.when(cRLModel.getCrlEncoded()).thenReturn(x509CRL.getEncoded());
        cRLStore.getCRL(issuerName);
        Mockito.verify(crlCacheWrapper).get(issuerName);
        Mockito.verify(cRLModel).getCrlEncoded();
    }

    private Cache<String, CRL> getCRL() throws CRLException, CertificateException, FileNotFoundException {
        final String cRLFileName = "VC_Root_CA_A1.crl";
        final String cRLAbsolutePath = CRLStore.class.getResource("/Crls/VC_Root_CA_A1.crl").getPath();
        x509CRL = generateCRLFromFactory(cRLAbsolutePath);
        cRLModel.setCrlEncoded(x509CRL.getEncoded());
        cRLCache.put(cRLFileName, cRLModel);
        return cRLCache;
    }

    private X509CRL generateCRLFromFactory(final String cRLfile) throws CertificateException, FileNotFoundException, CRLException {
        X509CRL x509CRL;
        CertificateFactory certificateFactory;
        certificateFactory = CertificateFactory.getInstance("x.509");
        final FileInputStream fileinputstream = new FileInputStream(cRLfile);
        x509CRL = (X509CRL) certificateFactory.generateCRL(fileinputstream);
        return x509CRL;
    }

}
