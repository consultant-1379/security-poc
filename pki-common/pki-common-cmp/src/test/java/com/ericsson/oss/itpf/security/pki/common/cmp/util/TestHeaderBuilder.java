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

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.InputTestData;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.model.PKIGeneralName;

@RunWith(MockitoJUnitRunner.class)
public class TestHeaderBuilder {
    private static RequestMessage requestMessage;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        requestMessage = InputTestData.createInitialRequestMessage();
    }

    @Test
    public void testCreate() {
        PKIGeneralName issuerGeneralName = new PKIGeneralName(new X500Name(requestMessage.getSenderName()));

        PKIHeaderBuilder headerBuilder = HeaderBuilder.create(requestMessage.getPKIMessage().getHeader(), issuerGeneralName);

        assertExpectedAndActual(headerBuilder);

    }

    private void assertExpectedAndActual(PKIHeaderBuilder headerBuilder) {
        PKIHeader responseHeader = headerBuilder.build();
        String base64TransactionId = constructBase64TransactionId(responseHeader);

        Assert.assertEquals(requestMessage.getBase64TransactionID(), base64TransactionId);
        Assert.assertEquals(requestMessage.getPKIHeader().getPvno(), responseHeader.getPvno());
    }

    private String constructBase64TransactionId(PKIHeader responseHeader) {
        final DEROctetString dos = (DEROctetString) (responseHeader.getTransactionID());
        String base64TransactionID = new String(org.bouncycastle.util.encoders.Base64.encode(dos.getOctets()));

        return base64TransactionID;
    }
}
