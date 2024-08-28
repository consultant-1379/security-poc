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
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender.CRLResponseMessageSender;

@RunWith(MockitoJUnitRunner.class)
public class CRLResponseMessageSenderTest {

    @InjectMocks
    CRLResponseMessageSender crlResponseMessageSender;

    @Mock
    private EventSender<CRLResponseMessage> crlResponseMessageEventSender;

    @Mock
    private Logger logger;

    private CRLResponseMessage crlMessage;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        crlMessage = new CRLResponseMessage();
        com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo crlInfo = new CRLInfo();
        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestingCertificate");
        caCertificateInfo.setCertificateSerialNumber("123456");
        crlInfo.setCaCertificateInfo(caCertificateInfo);
        List<com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo> crlInfoList = new ArrayList<CRLInfo>();
        crlMessage.setCrlInfoList(crlInfoList);
    }

    @Test
    public void sendMessage() {
        crlResponseMessageSender.sendMessage(crlMessage);
        Mockito.verify(logger).debug("End of sendMessage method in CrlsMessageSender class");
    }

}
