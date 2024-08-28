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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender;

import static org.mockito.Mockito.times;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender.CRLNotificationMessageSender;

@RunWith(MockitoJUnitRunner.class)
public class CRLNotificationMessageSenderTest {

    @InjectMocks
    CRLNotificationMessageSender crlNotificationMessageSender;

    @Mock
    private EventSender<CRLNotificationMessage> crlNotificationMessageEventSender;

    @Mock
    private Logger logger;

    private CRLNotificationMessage crlNotificationMessage;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        crlNotificationMessage = new CRLNotificationMessage();
        List<CACertificateInfo> caCertificateInfoList = new ArrayList<CACertificateInfo>();
        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestCACertificate");
        caCertificateInfo.setCertificateSerialNumber("123456");
        caCertificateInfoList.add(caCertificateInfo);
        crlNotificationMessage.setCaCertificateInfoList(caCertificateInfoList);
    }

    @Test
    public void sendMessage() {
        crlNotificationMessageSender.sendMessage(crlNotificationMessage);
        Mockito.verify(logger, times(1)).debug("End of sendMessage method in CRLNotificationMessageSender class");
    }

}
