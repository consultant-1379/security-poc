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
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.verify;
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
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.CreateAndGetEndEntityRequest;

public class EntityTest {

    @Mock
    CredMService credMService;

    @Mock
    Logger logger;

    @InjectMocks
    Entity endEntity;

    @Mock
    CredMRestAvailability credMPkiConfBean;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.rest.resources.EndEntity#createAndGetEndEntity(com.ericsson.oss.itpf.security.credmservice.api.rest.model.CreateAndGetEndEntityRequest)}
     * .
     *
     * @throws CredentialManagerInvalidProfileException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerInternalServiceException
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInvalidEntityException
     */

    @Test
    public void testCreateAndGetEndEntity() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerInvalidEntityException {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("localhost");
        subject.setOrganizationName("Ericsson");
        subject.setOrganizationalUnitName("EricssonOAM");

        final CredentialManagerEntity endEntity2 = new CredentialManagerEntity();
        endEntity2.setSubject(subject);

        // getProfile
        final String endEntityProfileName = "credMServiceProfile";
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        final CredentialManagerProfileInfo profile = new CredentialManagerProfileInfo();
        profile.setSubjectByProfile(subject);
        profile.setKeyPairAlgorithm(keyGenerationAlgorithm);
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile(endEntityProfileName)).thenReturn(profile);

        when(credMService.createAndGetEntity("localhost", subject, null, keyGenerationAlgorithm, endEntityProfileName)).thenReturn(endEntity2);

        final CreateAndGetEndEntityRequest entityRequest = new CreateAndGetEndEntityRequest();
        entityRequest.setHostname("localhost");
        entityRequest.setPassword("secret");

        final Response resp = endEntity.createAndGetEndEntity(entityRequest);
        Assert.assertTrue(subject.equals(((CredentialManagerEntity) resp.getEntity()).getSubject()));

        verify(credMService).createAndGetEntity(isA(String.class), isA(CredentialManagerSubject.class), isNull(CredentialManagerSubjectAltName.class),
                isA(CredentialManagerAlgorithm.class), isA(String.class));

        subject.setCommonName("");
        when(credMService.createAndGetEntity("CN=", subject, null, keyGenerationAlgorithm, endEntityProfileName))
                .thenThrow(new CredentialManagerInvalidArgumentException());
        final CreateAndGetEndEntityRequest entityRequest1 = new CreateAndGetEndEntityRequest();
        entityRequest1.setHostname("CN=");
        entityRequest1.setPassword("secret");
        final Response resp1 = endEntity.createAndGetEndEntity(entityRequest1);
        Assert.assertTrue(resp1.getStatus() == 500);

        subject.setCommonName("localhost2");
        when(credMService.createAndGetEntity("localhost2", subject, null, keyGenerationAlgorithm, endEntityProfileName))
                .thenThrow(new CredentialManagerInternalServiceException());
        final CreateAndGetEndEntityRequest entityRequest2 = new CreateAndGetEndEntityRequest();
        entityRequest2.setHostname("localhost2");
        entityRequest2.setPassword("secret");
        final Response resp2 = endEntity.createAndGetEndEntity(entityRequest2);
        Assert.assertTrue(resp2.getStatus() == 500);

        subject.setCommonName("localhost3");
        when(credMService.createAndGetEntity("CN=localhost3", subject, null, keyGenerationAlgorithm, endEntityProfileName))
                .thenThrow(new CredentialManagerInvalidEntityException());
        final CreateAndGetEndEntityRequest entityRequest3 = new CreateAndGetEndEntityRequest();
        entityRequest3.setHostname("CN=localhost3");
        entityRequest3.setPassword("secret");
        final Response resp3 = endEntity.createAndGetEndEntity(entityRequest3);
        Assert.assertTrue(resp3.getStatus() == 500);

    }

    //Exceptions for hard-coded profile name
    @Test
    public void testInvProfExGetEntity() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenThrow(new CredentialManagerInvalidProfileException());
        final Response resp = endEntity.createAndGetEndEntity(null);
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testProfNotFoundExGetEntity() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        when(credMService.getProfile("credMServiceProfile")).thenThrow(new CredentialManagerProfileNotFoundException());
        final Response resp = endEntity.createAndGetEndEntity(null);
        Assert.assertTrue(resp.getStatus() == 500);
    }

    @Test
    public void testWrongGetCertificate() {

        when(credMPkiConfBean.isEnabled()).thenReturn(false);

        final CreateAndGetEndEntityRequest entityRequest = new CreateAndGetEndEntityRequest();
        final Response resp = endEntity.createAndGetEndEntity(entityRequest);
        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
    }

}
