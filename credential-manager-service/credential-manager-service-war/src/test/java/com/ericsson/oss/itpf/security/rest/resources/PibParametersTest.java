package com.ericsson.oss.itpf.security.rest.resources;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;

public class PibParametersTest {

    @Mock
    CredMService credMService;
    
    @Mock
    Logger logger;

    @InjectMocks
    PibParameters pib;
    
    @Mock
    CredMRestAvailability credMPkiConfBean;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }
    
    @Test
    public void wrongGetPibParamsTest() {
        
        when(this.credMPkiConfBean.isEnabled()).thenReturn(false);
        
        final Response resp = this.pib.getPib();
        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
    }
    
    @Test
    public void getPibParamsTest() {
        
        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getPibParameters()).thenReturn(new CredentialManagerPIBParameters());
        
        final Response resp = this.pib.getPib();
        final CredentialManagerPIBParameters respPib = (CredentialManagerPIBParameters) resp.getEntity();
        assertTrue(respPib.getServiceCertAutoRenewalTimer() == 0 && respPib.isServiceCertAutoRenewalEnabled() && respPib.getServiceCertAutoRenewalWarnings().equals("0"));
        
        
    }
    
}
