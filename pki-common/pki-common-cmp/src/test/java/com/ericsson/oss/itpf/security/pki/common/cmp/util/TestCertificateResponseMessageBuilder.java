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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import static org.junit.Assert.assertEquals;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.InputTestData;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;

@RunWith(MockitoJUnitRunner.class)
public class TestCertificateResponseMessageBuilder {

    private static RequestMessage pKIIRRequestmessage;
    private static final String ISSUER_NAME = "MyRoot";
    private static String senderName;
    private static X509Certificate userCertificate;
    private static List<X509Certificate> trustedCertificates;

    @BeforeClass
    public static void setUpTestData() throws Exception {
        pKIIRRequestmessage = InputTestData.createInitialRequestMessage();
        senderName = pKIIRRequestmessage.getSenderName();
        userCertificate = CertificateResponseMessageBuilderUtility.identifyUserCertAndCertChains(pKIIRRequestmessage.getPKIMessage().getExtraCerts(), senderName);
        trustedCertificates = CertificateResponseMessageBuilderUtility.getVendorCertsList(ISSUER_NAME);
    }

    @Test
    public void test() throws Exception {
        trustedCertificates = CertificateResponseMessageBuilderUtility.getVendorCertsList(ISSUER_NAME);
        CertificateResponseMessageBuilder.build(0, userCertificate, trustedCertificates);
        assertEquals(PKIBody.TYPE_INIT_REQ, pKIIRRequestmessage.getPKIBody().getType());

    }

    @Test
    public void testBuildWaitingCertRepMessage() {

        CertificateResponseMessageBuilder.buildWaitingCertRepMessage(0);
        assertEquals(PKIBody.TYPE_INIT_REQ, pKIIRRequestmessage.getPKIBody().getType());

    }

}
