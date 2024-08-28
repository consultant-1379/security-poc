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
package com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource.listener;

import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEvent;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPCrlCacheLocalService;

@RunWith(MockitoJUnitRunner.class)
public class CrlResourceListenerTest {

    @InjectMocks
    CrlResourceListener crlResourceListener;

    @Mock
    FileResourceEvent fileResourceEvent;

    @Mock
    Resource resource;

    private final static String CRL_FILE = "VC_RBS_SubCA_A1_1";

    @Mock
    CMPCrlCacheLocalService crlCacheLocalService;

    @Mock
    ServiceFinderBean serviceFinderBean;

    @Mock
    Logger logger;

    @Test
    public void testOnEvent() throws CertificateException, CRLException, NoSuchProviderException, IOException, SecurityException, IllegalAccessException {
        MockitoAnnotations.initMocks(this);
        ReflectionTestUtils.setPrimitiveField(CrlResourceListener.class, ServiceFinderBean.class, "serviceFinder", crlResourceListener, serviceFinderBean);
        when(serviceFinderBean.find(CMPCrlCacheLocalService.class)).thenReturn(crlCacheLocalService);
        Mockito.when(fileResourceEvent.getResource()).thenReturn(resource);
        Mockito.when(fileResourceEvent.getResource().getName()).thenReturn(CRL_FILE);

        crlResourceListener.onEvent(fileResourceEvent);

        Mockito.verify(crlCacheLocalService).updateCrlCache(CRL_FILE);
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