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
package com.ericsson.oss.itpf.security.credmservice.configuration.listener;


import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;

@RunWith(MockitoJUnitRunner.class)
public class CredentialManagerConfigurationListenerTest {

    @InjectMocks
    CredentialManagerConfigurationListener credentialManagerConfigurationListener;

    @Mock
    private Logger logger;

    @Test
    public void getPibServiceCertAutoRenewalParameters() {
        final String warnings = "4,6";
        final int delay = 2;
        credentialManagerConfigurationListener.listenForServiceCertAutoRenewalWarnings(warnings);
        credentialManagerConfigurationListener.listenForServiceCertAutoRenewalEnabled(true);
        credentialManagerConfigurationListener.listenForServiceCertAutoRenewalTimer(2);
        String value = credentialManagerConfigurationListener.getPibServiceCertAutoRenewalWarnings();
        int timer = credentialManagerConfigurationListener.getPibServiceCertAutoRenewalTimer();
        boolean enabled = credentialManagerConfigurationListener.getPibServiceCertAutoRenewalEnabled();
        Assert.assertEquals(warnings, value);
        Assert.assertEquals(true, enabled);
        Assert.assertEquals(delay, timer);
        CredentialManagerPIBParameters parameters = credentialManagerConfigurationListener.getPibServiceParams();
        Assert.assertNotNull(parameters);
    }
}
