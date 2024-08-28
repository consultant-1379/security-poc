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
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetTrustResponse;

public class TrustTest {

    @Mock
    CredMService credMService;

    @Mock
    Logger logger;

    @InjectMocks
    Trust restTrust;

    @Mock
    CredMRestAvailability credMPkiConfBean;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetTrust() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {

        //final Map<String, CredentialManagerCertificateAuthority> trusts = new HashMap<String, CredentialManagerCertificateAuthority>();

        final CredentialManagerCertificateAuthority certAuth = new CredentialManagerCertificateAuthority("CN=rootCA");
        ///trusts.put("ericssonCA", certAuth);

        final CredentialManagerTrustMaps trustMaps = new CredentialManagerTrustMaps();
        trustMaps.getInternalCATrustMap().put("ericssonCA", certAuth);
        trustMaps.getExternalCATrustMap().put("externalCA", certAuth);

        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getTrustCertificates("credMServiceProfile")).thenReturn(trustMaps);
        //first case
        final Response resp = this.restTrust.getTrust();
        final GetTrustResponse trustInfo = (GetTrustResponse) resp.getEntity();
        Assert.assertTrue(trustInfo.getIntTrusts().containsKey("ericssonCA") && trustInfo.getExtTrusts().containsKey("externalCA"));
    }

    //Exceptions (at this point not all exception will be triggered because profile name here is hard-coded)
    @Test
    public void testCMInvArgumentExGetTrust() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getTrustCertificates("credMServiceProfile")).thenThrow(new CredentialManagerInvalidArgumentException());
        final Response resp = this.restTrust.getTrust();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMIntServiceExGetTrust() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getTrustCertificates("credMServiceProfile")).thenThrow(new CredentialManagerInternalServiceException());
        final Response resp = this.restTrust.getTrust();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMProfNotFoundExGetTrust() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getTrustCertificates("credMServiceProfile")).thenThrow(new CredentialManagerProfileNotFoundException());
        final Response resp = this.restTrust.getTrust();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMCertEncExGetTrust() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getTrustCertificates("credMServiceProfile")).thenThrow(new CredentialManagerCertificateEncodingException());
        final Response resp = this.restTrust.getTrust();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMInvProfExGetTrust() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        when(this.credMPkiConfBean.isEnabled()).thenReturn(true);
        when(this.credMService.getTrustCertificates("credMServiceProfile")).thenThrow(new CredentialManagerInvalidProfileException());
        final Response resp = this.restTrust.getTrust();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testWrongGetTrusts() {

        when(this.credMPkiConfBean.isEnabled()).thenReturn(false);

        final Response resp = this.restTrust.getTrust();
        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
    }
}
