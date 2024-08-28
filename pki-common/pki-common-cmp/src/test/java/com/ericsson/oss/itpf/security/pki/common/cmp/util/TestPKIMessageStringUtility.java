package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.InputTestData;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;

public class TestPKIMessageStringUtility {

    private static RequestMessage requestMessage;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        requestMessage = InputTestData.createInitialRequestMessage();
    }

    @Test
    public void testPrintPKIMessage() throws IOException {
        final boolean incomingMsg = true;
        PKIMessageStringUtility.printPKIMessage(incomingMsg, requestMessage.getPKIMessage(), requestMessage.getBase64TransactionID());
        assertEquals(PKIBody.TYPE_INIT_REQ, requestMessage.getPKIBody().getType());

    }

}
