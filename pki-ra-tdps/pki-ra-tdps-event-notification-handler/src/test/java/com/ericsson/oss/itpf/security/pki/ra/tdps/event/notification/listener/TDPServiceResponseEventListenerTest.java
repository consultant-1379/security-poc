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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.listener;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler.TDPServiceResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * 
 * @author tcsasma
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class TDPServiceResponseEventListenerTest {

    @InjectMocks
    TDPServiceResponseEventListener tdpsServiceResponseEventListener;

    @Mock
    TDPServiceResponseHandler tDPSResponseHandler;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testListenForTDPServiceResponse() {
        TDPServiceResponse tDPSServiceResponse = new TDPServiceResponse();
        List<TDPSCertificateInfo> tdpsCertificateInfoList = new ArrayList<TDPSCertificateInfo>();

        tDPSServiceResponse.setTdpsCertificateInfoList(tdpsCertificateInfoList);
        tdpsServiceResponseEventListener.listenForTDPServiceResponse(tDPSServiceResponse);

        Mockito.verify(tDPSResponseHandler).handle(tDPSServiceResponse);
    }

    @Test
    public void testListenTDPServiceResponseForErrorScenario() {
        TDPServiceResponse tDPSServiceResponse = new TDPServiceResponse();
        tdpsServiceResponseEventListener.listenForTDPServiceResponse(tDPSServiceResponse);

        Mockito.verify(logger).error("Received TDPSServiceResponse with empty CertificateInfoList. ");
    }

    @Test(expected = Exception.class)
    public void testListenForTDPServiceResponseException() {

        TDPServiceResponse tDPSServiceResponse = new TDPServiceResponse();
        List<TDPSCertificateInfo> tdpsCertificateInfoList = new ArrayList<TDPSCertificateInfo>();
        tDPSServiceResponse.setTdpsCertificateInfoList(tdpsCertificateInfoList);
        Mockito.doThrow(Exception.class).when(tDPSResponseHandler).handle(tDPSServiceResponse);

        tdpsServiceResponseEventListener.listenForTDPServiceResponse(tDPSServiceResponse);
        Mockito.verify(logger).error("Exception found while handling the TDPServiceResponse in TDPServiceResponseEventListener null");
    }
}
