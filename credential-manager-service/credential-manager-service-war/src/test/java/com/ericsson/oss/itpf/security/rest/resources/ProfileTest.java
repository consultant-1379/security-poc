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

import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

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
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ProfileTest extends Profile {

    @Mock
    CredMService credMService;

    @Mock
    Logger logger;

    @InjectMocks
    Profile restProfile;

    @Mock
    CredMRestAvailability credMPkiConfBean;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetProfile() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, JsonParseException, JsonMappingException,
            IOException {
        final CredentialManagerProfileInfo prof = new CredentialManagerProfileInfo();

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setOrganizationName("Ericsson");
        prof.setSubjectByProfile(subject);

        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenReturn(prof);
        final ObjectMapper om = new ObjectMapper();
        final Response resp = restProfile.getProfile();
        final String profileInfoStr = (String) resp.getEntity();
        final CredentialManagerProfileInfo profileInfo = om.readValue(profileInfoStr, CredentialManagerProfileInfo.class);
        Assert.assertTrue(subject.equals(profileInfo.getSubjectByProfile()));
        verify(credMService).getProfile(isA(String.class));
    }

    //Exceptions (profile hard-coded)
    @Test
    public void testCMInvExGetProfTest() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenThrow(new CredentialManagerInvalidArgumentException());
        final Response resp = restProfile.getProfile();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMIntServExGetProfTest() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenThrow(new CredentialManagerInternalServiceException());
        final Response resp = restProfile.getProfile();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMProfNotFoundExGetProfTest() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenThrow(new CredentialManagerProfileNotFoundException());
        final Response resp = restProfile.getProfile();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testCMInvProfExGetProfTest() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenThrow(new CredentialManagerInvalidProfileException());
        final Response resp = restProfile.getProfile();
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testWrongGetCertificate() {

        when(credMPkiConfBean.isEnabled()).thenReturn(false);

        final Response resp = restProfile.getProfile();
        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
    }
}
