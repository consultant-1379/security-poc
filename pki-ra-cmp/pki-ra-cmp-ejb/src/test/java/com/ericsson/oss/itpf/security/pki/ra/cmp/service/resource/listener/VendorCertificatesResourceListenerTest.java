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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEvent;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CmpCertificatesLocalService;

@RunWith(MockitoJUnitRunner.class)
public class VendorCertificatesResourceListenerTest {

    @InjectMocks
    VendorCertificatesResourceListener vendorCertificatesResourceListener;

    @Mock
    FileResourceEvent fileResourceEvent;

    @Mock
    CmpCertificatesLocalService cmpCertificatesLocalService;

    @Mock
    ServiceFinderBean serviceFinderBean;

    @Mock
    Logger logger;

    @Test
    public void testOnEvent() throws SecurityException, IllegalAccessException {
        MockitoAnnotations.initMocks(this);
        ReflectionTestUtils.setPrimitiveField(VendorCertificatesResourceListener.class, ServiceFinderBean.class, "serviceFinder", vendorCertificatesResourceListener, serviceFinderBean);
        when(serviceFinderBean.find(CmpCertificatesLocalService.class)).thenReturn(cmpCertificatesLocalService);
        vendorCertificatesResourceListener.onEvent(fileResourceEvent);
        Mockito.verify(cmpCertificatesLocalService).initializeVendorCertificates();

    }

    @Test
    public void testGetURI() {
        Assert.assertNull(vendorCertificatesResourceListener.getURI());
    }

    @Test
    public void testGetEventTypes() {
        Assert.assertNull(vendorCertificatesResourceListener.getEventTypes());
    }

}