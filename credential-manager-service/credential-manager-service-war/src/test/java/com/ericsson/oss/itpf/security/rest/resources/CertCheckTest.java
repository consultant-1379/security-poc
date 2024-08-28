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
package com.ericsson.oss.itpf.security.rest.resources;

import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;

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
import com.ericsson.oss.itpf.security.credmservice.ejb.startup.JcaFileResourceBean;

public class CertCheckTest {

    @Mock
    CredMService credMService;

    @Mock
    Logger logger;

    @Mock
    JcaFileResourceBean resourceBean;

    @Mock
    CredMRestAvailability credMPkiConfBean;

    @InjectMocks
    CertCheck certCheck;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void checkPropertiesCronValueTest() {
        when(credMPkiConfBean.isEnabled()).thenReturn(false).thenReturn(true);
        Response resp = certCheck.checkPropertiesCronValues();

        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
        resp = certCheck.checkPropertiesCronValues();
        Assert.assertEquals(resp.getStatus(), Status.NO_CONTENT.getStatusCode());
    }

    @Test
    public void removePropertiesCronValuesTest() {
        when(credMPkiConfBean.isEnabled()).thenReturn(false).thenReturn(true);
        Response resp = certCheck.removePropertiesCronValues();

        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
        resp = certCheck.removePropertiesCronValues();
        Assert.assertEquals(resp.getStatus(), Status.NO_CONTENT.getStatusCode());
    }

    @Test
    public void writedefPropertiesCronValuesTest() throws NoSuchAlgorithmException {
        when(credMPkiConfBean.isEnabled()).thenReturn(false).thenReturn(true);
        Response resp = certCheck.writedefPropertiesCronValues();
        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());

        resp = certCheck.writedefPropertiesCronValues();
        Assert.assertEquals(null, resp);

        when(resourceBean.supportsWriteOperations()).thenReturn(true);
        resp = certCheck.writedefPropertiesCronValues();
        Assert.assertEquals(resp.getStatus(), Status.OK.getStatusCode());

    }

}
