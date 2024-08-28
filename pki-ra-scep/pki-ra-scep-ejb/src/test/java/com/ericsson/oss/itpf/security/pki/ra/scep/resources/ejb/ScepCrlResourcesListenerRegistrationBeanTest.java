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
package com.ericsson.oss.itpf.security.pki.ra.scep.resources.ejb;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
public class ScepCrlResourcesListenerRegistrationBeanTest {

    @InjectMocks
    ScepCrlResourcesListenerRegistrationBean scepCrlResourcesListenerRegistrationBean;

    @Mock
    Logger logger;

    @Mock
    ConfigurationListener configurationListener;

    private final static String cRLPath = "/ericsson/pkira/data/crls/SCEP_CRLStore";

    private final static String LISTENER_REGISTER_SUCCESS = "End of registerResourceListeners method in ScepCrlResourcesListenerRegistrationBean Class";

    @Test
    public void testRegisterResourceListeners() {

        Mockito.when(configurationListener.getScepCRLPath()).thenReturn(cRLPath);

        PowerMockito.mockStatic(Resources.class);

        scepCrlResourcesListenerRegistrationBean.registerResourceListeners();
        Mockito.verify(logger).info(LISTENER_REGISTER_SUCCESS);
    }
}
