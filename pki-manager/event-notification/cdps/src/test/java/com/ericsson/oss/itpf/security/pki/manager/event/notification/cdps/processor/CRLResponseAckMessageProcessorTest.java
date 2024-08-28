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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor;

import java.util.ArrayList;

import java.util.List;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.*;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementLocalService;

@RunWith(MockitoJUnitRunner.class)
public class CRLResponseAckMessageProcessorTest {

    @InjectMocks
    CRLResponseAckMessageProcessor crlResponseAckMessageProcessor;

    @Mock
    private CACertificateInfoEventMapper caCertificateInfoEventMapper;

    @Mock
    public CRLManagementLocalService crlManagementLocalService;

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
    public void process() {
        crlResponseAckMessageProcessor.process(crlResponseAckMessage);
    }

    @Test
    public void testProcess_CDPSResponseType_FAILURE() {
        crlResponseAckMessage.setCdpsResponseType(CDPSResponseType.FAILURE);
        crlResponseAckMessageProcessor.process(crlResponseAckMessage);
    }

    @Test
    public void testProcessCDPSOperationType_UNPUBLISH() {
        crlResponseAckMessage.setCdpsOperationType(CDPSOperationType.UNPUBLISH);
        crlResponseAckMessage.setCdpsResponseType(CDPSResponseType.SUCCESS);
        crlResponseAckMessage.setUnpublishReasonType(UnpublishReasonType.EXPIRED_CA_CERTIFICATE);
        crlResponseAckMessageProcessor.process(crlResponseAckMessage);
    }

    @Test
    public void testProcess_UnpublishReasonType() {
        crlResponseAckMessage.setCdpsOperationType(CDPSOperationType.UNPUBLISH);
        crlResponseAckMessage.setCdpsResponseType(CDPSResponseType.SUCCESS);
        crlResponseAckMessage.setUnpublishReasonType(null);
        crlResponseAckMessageProcessor.process(crlResponseAckMessage);

    }

}
