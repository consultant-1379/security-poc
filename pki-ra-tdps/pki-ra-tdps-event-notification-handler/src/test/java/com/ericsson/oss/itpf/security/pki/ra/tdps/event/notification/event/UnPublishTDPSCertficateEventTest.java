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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.event;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.instrumentation.TDPSInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender.TDPSAcknowledgementEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.api.TDPSLocalService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * 
 * @author tcsasma
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class UnPublishTDPSCertficateEventTest {

    @InjectMocks
    UnPublishTDPSCertficateEvent unPublishTDPSCertficateEvent;

    @Mock
    TDPSLocalService tdpsLocalService;

    @Mock
    TDPSEntityDataMapper tDPSEntityDataMapper;

    @Mock
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Mock
    TDPSResponseMapper tDPSResponseMapper;

    @Mock
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Mock
    TDPSAcknowledgementEventSender tdpsAcknowledgementEventSender;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    TDPSInstrumentationBean tdpsInstrumentationBean;

    private static TDPSCertificateEvent tDPSCertificateEvent;

    private static TDPSCertificateInfo tdpsCertificateInfo;
    private static List<TDPSCertificateInfo> listTDPSCertificateInfo;

    @Test
    public void testExecute() {

        setupData();

        unPublishTDPSCertficateEvent.execute(tDPSCertificateEvent);
        Mockito.verify(tdpsAcknowledgementEventSender).send(Matchers.<TDPSAcknowledgementEvent> anyObject());
    }

    @Test
    public void testExecuteTDPSEntityDataNotNull() {
        setupData();

        unPublishTDPSCertficateEvent.execute(tDPSCertificateEvent);
        Mockito.verify(tdpsAcknowledgementEventSender).send(Matchers.<TDPSAcknowledgementEvent> anyObject());
    }

    @Test
    public void testExecuteException() {
        setupData();
        Mockito.doThrow(Exception.class).when(tdpsLocalService).unPublishTDPSCertificates(tdpsCertificateInfo);
        unPublishTDPSCertficateEvent.execute(tDPSCertificateEvent);
        Mockito.verify(logger).error("Certificate with entity name as {} with certificate serialNo as {} was not found in TDPS. Hence assuming it was already unpublished",
                tdpsCertificateInfo.getEntityName(), tdpsCertificateInfo.getSerialNumber());
    }

    public void setupData() {
        listTDPSCertificateInfo = new ArrayList<TDPSCertificateInfo>();

        tDPSCertificateEvent = new TDPSCertificateEvent();
        tdpsCertificateInfo = new TDPSCertificateInfo();

        listTDPSCertificateInfo.add(tdpsCertificateInfo);

        tdpsCertificateInfo.setEntityName("end_entity");
        tdpsCertificateInfo.setSerialNumber("13456rt784u");
        tdpsCertificateInfo.setIssuerName("issuer");
        TDPSEntityType tdpsEntityType = TDPSEntityType.ENTITY;
        tdpsCertificateInfo.setTdpsEntityType(tdpsEntityType);
        tDPSCertificateEvent.setTdpsCertificateInfos(listTDPSCertificateInfo);
    }

}
