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
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;

public class TestPKIStatusInfoMapper {

    @Test
    public void testMapBagMsgCheck() {
        PKIStatusInfo pkiStatusInfo = PKIStatusInfoMapper.map(ErrorMessages.BAD_MESSAGE_CHECK);
        Assert.assertEquals(BigInteger.valueOf(2), pkiStatusInfo.getStatus());
        Assert.assertEquals(pkiStatusInfo.getStatusString(), new PKIFreeText(new DERUTF8String(ErrorMessages.BAD_MESSAGE_CHECK)));
        assertNotNull(PKIStatusInfoMapper.map("BAD_MESSAGE_CHECK"));
    }

    @Test
    public void testMapTransactionIDInUse() {
        PKIStatusInfo pkiStatusInfo = PKIStatusInfoMapper.map(ErrorMessages.TRANSACTION_ID_IN_USE);
        Assert.assertEquals(BigInteger.valueOf(2), pkiStatusInfo.getStatus());
        Assert.assertEquals(pkiStatusInfo.getStatusString(), new PKIFreeText(new DERUTF8String(ErrorMessages.TRANSACTION_ID_IN_USE)));
        assertNotNull(PKIStatusInfoMapper.map("TRANSACTION_ID_IN_USE"));
    }

    @Test
    public void testMapNotSupportedRequestType() {
        PKIStatusInfo pkiStatusInfo = PKIStatusInfoMapper.map(ErrorMessages.NOT_SUPPORTED_REQUEST_TYPE);
        Assert.assertEquals(BigInteger.valueOf(2), pkiStatusInfo.getStatus());
        Assert.assertEquals(pkiStatusInfo.getStatusString(), new PKIFreeText(new DERUTF8String(ErrorMessages.NOT_SUPPORTED_REQUEST_TYPE)));
        assertNotNull(PKIStatusInfoMapper.map("NOT_SUPPORTED_REQUEST_TYPE"));
    }

    @Test
    public void testMapHeaderSenderFormatError() {
        PKIStatusInfo pkiStatusInfo = PKIStatusInfoMapper.map(ErrorMessages.HEADER_SENDER_FORMAT_ERROR);
        Assert.assertEquals(BigInteger.valueOf(2), pkiStatusInfo.getStatus());
        assertNotNull(PKIStatusInfoMapper.map("HEADER_SENDER_FORMAT_ERROR"));
    }

}
