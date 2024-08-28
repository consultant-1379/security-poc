/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.rest.resources;

import javax.ws.rs.core.Response;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@PrepareForTest({ Profile.class })
@RunWith(PowerMockRunner.class)
public class ProfileExceptionTest {

    @Mock
    CredMService credMService;

    @Mock
    Logger logger;

    @InjectMocks
    Profile restProfile;

    @Mock
    CredMRestAvailability credMPkiConfBean;


    @SuppressWarnings("deprecation")
    @Test
    public void testJsonProcessingExceptionExGetProfTest() {
        PowerMockito.when(credMPkiConfBean.isEnabled()).thenReturn(true);
        PowerMockito.when(credMService.getProfile("credMServiceProfile")).thenReturn(null);

        final ObjectMapper om = PowerMockito.mock(ObjectMapper.class);
        try {
            PowerMockito.whenNew(ObjectMapper.class).withAnyArguments().thenReturn(om);
            PowerMockito.when(om.writeValueAsString(Mockito.anyObject())).thenThrow(new JsonProcessingException("Error") {
            });


        } catch (final Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        final Response resp = restProfile.getProfile();
    }


}
