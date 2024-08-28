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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.listener;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.*;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.listener.CRLResponseAckMessageListener;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor.CRLResponseAckMessageProcessor;

@RunWith(MockitoJUnitRunner.class)
public class CRLResponseAckMessageListenerTest {

    @InjectMocks
    CRLResponseAckMessageListener crlResponseAckMessageListener;

    @Mock
    private CRLResponseAckMessageProcessor crlResponseAckMessageProcessor;

    @Mock
    private Logger logger;

    private CRLResponseAckMessage crlResponseAckMessage;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        crlResponseAckMessage = new CRLResponseAckMessage();
        List<CACertificateInfo> caCertificateInfoList = new ArrayList<CACertificateInfo>();
        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestingCACertificate");
        caCertificateInfo.setCertificateSerialNumber("123456");
        caCertificateInfoList.add(caCertificateInfo);
        crlResponseAckMessage.setCaCertificateInfoList(caCertificateInfoList);
        crlResponseAckMessage.setCdpsOperationType(CDPSOperationType.PUBLISH);
        crlResponseAckMessage.setCdpsResponseType(CDPSResponseType.SUCCESS);
        crlResponseAckMessage.setUnpublishReasonType(UnpublishReasonType.EXPIRED_CA_CERTIFICATE);
    }

    @Test
    public void receiveCRLResponseAckMessage() {
        crlResponseAckMessageListener.receiveCRLResponseAckMessage(crlResponseAckMessage);
    }

}
