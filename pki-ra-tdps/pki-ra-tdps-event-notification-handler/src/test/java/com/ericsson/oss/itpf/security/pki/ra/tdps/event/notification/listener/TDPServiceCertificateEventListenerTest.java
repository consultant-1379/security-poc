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
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler.TDPSCertificateEventHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * 
 * @author tcsasma
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class TDPServiceCertificateEventListenerTest {

    @InjectMocks
    TDPServiceCertificateEventListener tdpsServiceCertificateEventListener;

    @Mock
    TDPSCertificateEventHandler tDPSCertificateEventHandler;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testListenForCertificateEvent() {
        List<TDPSCertificateInfo> listTDPSCertificateInfo = new ArrayList<TDPSCertificateInfo>();
        TDPSCertificateEvent tdpsCertificateEventResponse = new TDPSCertificateEvent();
        TDPSCertificateInfo tdpsCertificateInfo = new TDPSCertificateInfo();
        listTDPSCertificateInfo.add(tdpsCertificateInfo);
        tdpsCertificateEventResponse.setTdpsCertificateInfos(listTDPSCertificateInfo);
        tdpsCertificateEventResponse.setTdpsOperationType(TDPSOperationType.PUBLISH);
        tdpsServiceCertificateEventListener.listenForCertificateEvent(tdpsCertificateEventResponse);
        Mockito.verify(tDPSCertificateEventHandler).handle(tdpsCertificateEventResponse);
    }

    @Test
    public void testListenCertificateEventForErrorCase() {
        TDPSCertificateEvent tdpsCertificateEventResponse = new TDPSCertificateEvent();
        tdpsCertificateEventResponse.setTdpsOperationType(TDPSOperationType.PUBLISH);
        tdpsServiceCertificateEventListener.listenForCertificateEvent(tdpsCertificateEventResponse);
        Mockito.verify(logger).error("Certificate Event does not contain any valid Data i.e CertificateInfo is NULL");
    }

    @Test(expected = Exception.class)
    public void testListenForCertificateEventException() {

        List<TDPSCertificateInfo> listTDPSCertificateInfo = new ArrayList<TDPSCertificateInfo>();
        TDPSCertificateEvent tdpsCertificateEventResponse = new TDPSCertificateEvent();
        TDPSCertificateInfo tdpsCertificateInfo = new TDPSCertificateInfo();
        listTDPSCertificateInfo.add(tdpsCertificateInfo);
        tdpsCertificateEventResponse.setTdpsCertificateInfos(listTDPSCertificateInfo);
        Mockito.doThrow(Exception.class).when(tDPSCertificateEventHandler).handle(tdpsCertificateEventResponse);

        tdpsServiceCertificateEventListener.listenForCertificateEvent(tdpsCertificateEventResponse);
        Mockito.verify(logger).error("Exception found while publishing/Unpublishing Certificates in TDPS in TDPServiceCertificateEventListener null");
    }
}
