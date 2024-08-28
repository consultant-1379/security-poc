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
package com.ericsson.oss.itpf.security.pki.ra.scep.ejb;

import java.io.FileNotFoundException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.CrlCacheException;

@RunWith(MockitoJUnitRunner.class)
public class ScepCrlCacheLoaderBeanTest {

    @Mock
    ScepCrlCacheUtil scepCrlCacheUtil;

    @InjectMocks
    ScepCrlCacheLoaderBean scepCrlCacheLoaderBean;

    @Mock
    Logger logger;
    
    @Mock
    private SystemRecorder systemRecorder;

    @Test
    public void testLoad() throws CertificateException, FileNotFoundException, CRLException {
        scepCrlCacheLoaderBean.load();
        Mockito.verify(scepCrlCacheUtil).initializeCRLCache();

    }

    @Test
    public void testLoadNegative() {
        Mockito.doThrow(new CrlCacheException("CRLCache Exception occurred")).when(scepCrlCacheUtil).initializeCRLCache();
        try {
            scepCrlCacheLoaderBean.load();
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().equals("CRLCache Exception occurred"));
        }

    }
}
