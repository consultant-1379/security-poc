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
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CRLResponseMessageBuilder;

@RunWith(MockitoJUnitRunner.class)
public class CRLResponseMessageBuilderTest {

    private CRLResponseMessageBuilder crlResponseMessageBuilder;

    private List<CRLInfo> crlInfos;

    @Before
    public void setUp() {
        crlResponseMessageBuilder = new CRLResponseMessageBuilder();
        CRLInfo crlInfo = new CRLInfo();
        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestingCACertificate");
        caCertificateInfo.setCertificateSerialNumber("123456");
        crlInfo.setCaCertificateInfo(caCertificateInfo);
        crlInfo.setEncodedCRL("abcdefg".getBytes());
        crlInfos = new ArrayList<CRLInfo>();
        crlInfos.add(crlInfo);

    }

    @Test
    public void testCrlInfos() {
        CRLResponseMessageBuilder returnObj = crlResponseMessageBuilder.crlInfos(crlInfos);
        Assert.assertNotNull(returnObj);
    }

    @Test
    public void testBuild() {
        CRLResponseMessage crlResponseMessageReturn = new CRLResponseMessage();
        crlResponseMessageReturn.setCrlInfoList(crlInfos);
        crlResponseMessageBuilder.build();
        Assert.assertNotNull(crlResponseMessageReturn.getCrlInfoList());
    }

}
