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
package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.CertExpiryNotificationsConstants;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.InternalAlarmGenerator;

@RunWith(MockitoJUnitRunner.class)
@PrepareForTest({ ClientResponse.class, ClientRequest.class, InternalAlarmGenerator.class })
public class InternalAlarmGeneratorTest {

    @InjectMocks
    private InternalAlarmGenerator internalAlarmGenerator;

    @Mock
    private ClientRequest request;

    @Mock
    private ClientResponse<String> response;

    @Spy
    Logger logger = LoggerFactory.getLogger(InternalAlarmGeneratorTest.class);

    @Mock
    protected SystemRecorder systemRecorder;

    @Test
    public void test_raiseInternalAlarmSuccess() throws Exception {
        MockitoAnnotations.initMocks(this);
        final Map<String, Object> alarmDetails = new HashMap<String, Object>();
        alarmDetails.put(CertExpiryNotificationsConstants.EVENT_TYPE, "CERTIFICATE EXPIRY NOTIFICATION");
        alarmDetails
                .put(CertExpiryNotificationsConstants.PROBABLE_CAUSE,
                        "Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.");
        alarmDetails.put(CertExpiryNotificationsConstants.SPECIFIC_PROBLEM, "CERTIFICATE EXPIRY");
        alarmDetails.put(CertExpiryNotificationsConstants.PERCEIVED_SEVERITY, "MAJOR");
        alarmDetails.put(CertExpiryNotificationsConstants.RECORD_TYPE, " ALARM");
        alarmDetails.put(CertExpiryNotificationsConstants.MANAGED_OBJECT_INSTANCE, "Security-PKI");
        // try {
        request = PowerMockito.mock(ClientRequest.class);

        response = PowerMockito.mock(ClientResponse.class);

        PowerMockito.whenNew(ClientRequest.class).withArguments(Mockito.anyString()).thenReturn(request);

        PowerMockito.when(request.post((String.class))).thenAnswer(new Answer<ClientResponse<String>>() {

            @Override
            public ClientResponse<String> answer(InvocationOnMock invocation) throws Throwable {

                return response;
            }
        });

        Mockito.when(response.getStatus()).thenReturn(Response.Status.OK.getStatusCode());
        /*
         * } catch (Exception e1) { e1.printStackTrace(); }
         */

        internalAlarmGenerator.raiseInternalAlarm(alarmDetails);
        verify(systemRecorder, times(0)).recordEvent(Matchers.anyString(), Matchers.any(EventLevel.class), Matchers.anyString(), Matchers.anyString(), Matchers.anyString());
    }

    @Test
    public void test_raiseInternalAlarmFailure() throws JsonGenerationException, JsonMappingException, IOException {
        MockitoAnnotations.initMocks(this);
        final Map<String, Object> alarmDetails = new HashMap<String, Object>();
        alarmDetails.put(CertExpiryNotificationsConstants.EVENT_TYPE, "CERTIFICATE EXPIRY NOTIFICATION");
        alarmDetails
                .put(CertExpiryNotificationsConstants.PROBABLE_CAUSE,
                        "Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.");
        alarmDetails.put(CertExpiryNotificationsConstants.SPECIFIC_PROBLEM, "CERTIFICATE EXPIRY");
        alarmDetails.put(CertExpiryNotificationsConstants.PERCEIVED_SEVERITY, "MAJOR");
        alarmDetails.put(CertExpiryNotificationsConstants.RECORD_TYPE, " ALARM");
        alarmDetails.put(CertExpiryNotificationsConstants.MANAGED_OBJECT_INSTANCE, "Security-PKI");
        request = PowerMockito.mock(ClientRequest.class);

        response = PowerMockito.mock(ClientResponse.class);
        try {
            PowerMockito.whenNew(ClientRequest.class).withArguments(Mockito.anyString()).thenReturn(request);

            PowerMockito.when(request.post((String.class))).thenAnswer(new Answer<ClientResponse<String>>() {

                public ClientResponse<String> answer(InvocationOnMock invocation) throws Throwable {

                    return response;
                }
            });

            Mockito.when(response.getStatus()).thenReturn(Response.Status.PRECONDITION_FAILED.getStatusCode());
        } catch (Exception e1) {
            e1.printStackTrace();
        }

        internalAlarmGenerator.raiseInternalAlarm(alarmDetails);
        verify(systemRecorder, times(1)).recordError(Matchers.anyString(), Matchers.any(ErrorSeverity.class), Matchers.anyString(), Matchers.anyString(), Matchers.anyString());
    }
}
