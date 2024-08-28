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
package com.ericsson.oss.itpf.security.pki.cdps.notification;

import static org.mockito.Mockito.times;

import java.util.List;




import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent;
import com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation.CRLInstrumentationBean;

/**
 * This class used to test PublishCRLEvent functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLNotificationMessageListenerTest {

    @InjectMocks
    CRLNotificationMessageListener crlNotificationMessageListener;

    @Mock
    CRLAcknowledgementSender crlAcknowledgementSender;

    @Mock
    CRLRequestMessageSender crlRequestMessageSender;

    @Mock
    private Logger logger;

    @Mock
    private UnpublishCRLEvent unPublishCRLEvent;

    @Mock
    private SystemRecorder systemRecorder;
    
    @Mock
    CRLInstrumentationBean crlInstrumentationBean;

    private CRLNotificationMessage crlNotificationMsgPublish;

    private CRLNotificationMessage crlNotificationMsgUnPublish;

    private List<CACertificateInfo> caCertInfoList;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        crlNotificationMsgPublish = new CRLNotificationMessage();
        crlNotificationMsgPublish.setCaCertificateInfoList(caCertInfoList);
        crlNotificationMsgPublish.setCdpsOperationType(CDPSOperationType.PUBLISH);

        crlNotificationMsgUnPublish = new CRLNotificationMessage();
        crlNotificationMsgUnPublish.setCaCertificateInfoList(caCertInfoList);
        crlNotificationMsgUnPublish.setCdpsOperationType(CDPSOperationType.UNPUBLISH);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.cdps.notification.CRLNotificationMessageListener#listenForCRLNotificationMessageEvents(com.ericsson.oss.itpf.security.pki.ra.cdps.event.CRLNotificationMessage)}
     * .
     */
    @Test
    public void testListenForCRLNotificationMessageEventsPublish() {

        crlNotificationMessageListener.listenForCRLNotificationMessageEvents(crlNotificationMsgPublish);

        Mockito.verify(logger, times(1)).debug("Begin of handleMessage of CRLNotificationMessageListener class");
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.cdps.notification.CRLNotificationMessageListener#listenForCRLNotificationMessageEvents(com.ericsson.oss.itpf.security.pki.ra.cdps.event.CRLNotificationMessage)}
     * .
     */
    @Test
    public void testListenForCRLNotificationMessageEventsUnPublish() {

        crlNotificationMessageListener.listenForCRLNotificationMessageEvents(crlNotificationMsgUnPublish);

        Mockito.verify(logger, times(1)).debug("Begin of handleMessage of CRLNotificationMessageListener class");
    }

}
