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
package com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils;

import java.io.IOException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.Assert;
import org.mockito.Mock;
import org.slf4j.Logger;

public class ResponseBuilderTestUtil {
    @Mock
    static Logger logger;

    private ResponseBuilderTestUtil() {

    }

    static PKIMessage pKIMessage = null;

    public static PKIMessage pKIMessageFromByteArray(final byte[] inputByteArray) throws IOException {
        PKIMessage pKIMessage = null;
        final ASN1InputStream inputStream = new ASN1InputStream(inputByteArray);
        final ASN1Primitive rawMessage = inputStream.readObject();
        pKIMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(rawMessage));
        inputStream.close();
        return pKIMessage;
    }

    public static void assertCheck(final PKIMessage pKIMessage, final PKIMessage pkiResponseMessage) {
        Assert.assertEquals(pKIMessage.getHeader().getTransactionID(), pkiResponseMessage.getHeader().getTransactionID());

        Assert.assertEquals(pKIMessage.getHeader().getPvno(), pkiResponseMessage.getHeader().getPvno());

        Assert.assertEquals(pKIMessage.getHeader().getSender().getTagNo(), pkiResponseMessage.getHeader().getSender().getTagNo());

        Assert.assertEquals(pKIMessage.getHeader().getRecipient().getTagNo(), pkiResponseMessage.getHeader().getRecipient().getTagNo());

        Assert.assertEquals(pKIMessage.getHeader().getProtectionAlg().getAlgorithm(), pkiResponseMessage.getHeader().getProtectionAlg().getAlgorithm());

    }

}
