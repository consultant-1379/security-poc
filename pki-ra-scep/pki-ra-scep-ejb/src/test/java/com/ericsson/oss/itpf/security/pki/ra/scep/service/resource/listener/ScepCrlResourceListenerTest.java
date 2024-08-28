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
package com.ericsson.oss.itpf.security.pki.ra.scep.service.resource.listener;

import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEvent;
import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;
import com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api.ScepCrlCacheLocalService;
import com.ericsson.oss.itpf.security.pki.ra.scep.service.resource.listener.ScepCrlResourceListener;

@RunWith(MockitoJUnitRunner.class)
public class ScepCrlResourceListenerTest {

    @InjectMocks
    ScepCrlResourceListener crlResourceListener;

    @Mock
    FileResourceEvent fileResourceEvent;

    @Mock
    Resource resource;

    @Mock
    ScepCrlCacheUtil scepCrlCacheUtil;
    
    @Mock
    ServiceFinderBean mockServiceFinder;
    
    @Mock
    ScepCrlCacheLocalService scepCrlCacheLocalService;

    private final static String CRL_FILE = "SCEPCRL_ENM_Management_CA.crl";
    
    @Test
    public void testOnEvent() throws CertificateException, CRLException, NoSuchProviderException, IOException, SecurityException, IllegalAccessException {
        MockitoAnnotations.initMocks(this);
        ReflectionTestUtils.setPrimitiveField(ScepCrlResourceListener.class, ServiceFinderBean.class, "serviceFinder", crlResourceListener, mockServiceFinder);
        when(mockServiceFinder.find(ScepCrlCacheLocalService.class)).thenReturn(scepCrlCacheLocalService);
        Mockito.when(fileResourceEvent.getResource()).thenReturn(resource);
        Mockito.when(fileResourceEvent.getResource().getName()).thenReturn(CRL_FILE);

        crlResourceListener.onEvent(fileResourceEvent);

        Mockito.verify(scepCrlCacheLocalService).updateCrlCache(CRL_FILE);
    }

    @Test
    public void testGetURI() {
        Assert.assertNull(crlResourceListener.getURI());
    }

    @Test
    public void testGetEventTypes() {
        Assert.assertNull(crlResourceListener.getEventTypes());
    }

}
