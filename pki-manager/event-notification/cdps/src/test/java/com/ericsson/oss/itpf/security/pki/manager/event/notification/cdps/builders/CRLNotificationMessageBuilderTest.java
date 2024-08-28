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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CRLNotificationMessageBuilder;

@RunWith(MockitoJUnitRunner.class)
public class CRLNotificationMessageBuilderTest {

    @InjectMocks
    CRLNotificationMessageBuilder crlNotificationMessageBuilder;

    private List<CACertificateInfo> caCertificateInfos;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        caCertificateInfos = new ArrayList<CACertificateInfo>();
        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestingCACertificateInfo");
        caCertificateInfo.setCertificateSerialNumber("123456");
        caCertificateInfos.add(caCertificateInfo);

    }

    @Test
    public void testCaCertificateInfos() {

        CRLNotificationMessageBuilder answer = crlNotificationMessageBuilder.caCertificateInfos(caCertificateInfos);
        Assert.assertNotNull(answer);

    }

    @Test
    public void testCdpsOperationType() {

        CRLNotificationMessageBuilder answer = crlNotificationMessageBuilder.cdpsOperationType(CDPSOperationType.PUBLISH);
        Assert.assertNotNull(answer);
    }

    @Test
    public void testUnpublishReasonType() {

        CRLNotificationMessageBuilder answer = crlNotificationMessageBuilder.unpublishReasonType(UnpublishReasonType.EXPIRED_CA_CERTIFICATE);
        Assert.assertNotNull(answer);
    }

    @Test
    public void testBuild() {
        CRLNotificationMessage returnObj = crlNotificationMessageBuilder.build();
        Assert.assertNotNull(returnObj);
    }
}