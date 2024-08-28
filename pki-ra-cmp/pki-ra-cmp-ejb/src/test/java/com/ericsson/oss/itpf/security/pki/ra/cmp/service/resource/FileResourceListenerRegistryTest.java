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
package com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource.FileResourceListenerRegistry;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
public class FileResourceListenerRegistryTest {

    @InjectMocks
    FileResourceListenerRegistry fileResourceListenerRegistry;

    @Mock
    Logger logger;

    @Mock
    ConfigurationParamsListener configurationListener;

    @Mock
    SystemRecorder systemRecorder;

    private final static String vendorCertificatesPath = "/ericsson/pkira/data/certs/CMPRAExternalTrustStore.jks";
    private final static String caCertificatesPath = "/ericsson/pkira/data/certs/CMPRAInternalTrustStore.jks";
    private final static String crlPath = "/ericsson/pkira/data/crls/CMP_CRLStore";

    private final static String LISTENER_REGISTER_SUCCESS = "Successfully registered resources listeners with listen directory path location for internal/external trusts and CRL";

    @Test
    public void testRegisterCertificatesResourceListeners() {

        Mockito.when(configurationListener.getVendorCertPath()).thenReturn(vendorCertificatesPath);
        Mockito.when(configurationListener.getCACertPath()).thenReturn(caCertificatesPath);
        Mockito.when(configurationListener.getCRLPath()).thenReturn(crlPath);

        PowerMockito.mockStatic(Resources.class);

        fileResourceListenerRegistry.registerResourceListeners();
        Mockito.verify(logger).info(LISTENER_REGISTER_SUCCESS);
    }
}