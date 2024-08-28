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

import javax.naming.InvalidNameException;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.UnsupportedRequestTypeException;

public class TestPKIMessageUtil {

    private static RequestMessage ipRequestmessage;
    private static RequestMessage pollRequestMessage;
    private static final String ENTITY = "Entity";

    @BeforeClass
    public static void prepareTestData() throws Exception {
        ipRequestmessage = InputTestData.createInitialRequestMessage();
        pollRequestMessage = InputTestData.createPollRequestMessage();
    }

    @Test
    public void testGetSubjectCNfromPKIMessage() throws UnsupportedRequestTypeException, InvalidNameException {
        String entityCN = PKIMessageUtil.getSubjectCNfromPKIMessage(ipRequestmessage.getPKIMessage());
        assertEquals(ENTITY, entityCN);
    }

    @Test(expected = UnsupportedRequestTypeException.class)
    public void testGetSubjectCNfromPKIMessageForException() throws UnsupportedRequestTypeException, InvalidNameException {
        PKIMessageUtil.getSubjectCNfromPKIMessage(pollRequestMessage.getPKIMessage());
    }

    @Test
    public void testConvertRequestTypeToString_ForIR() {
        String requestMessage = PKIMessageUtil.convertRequestTypeToString(PKIBody.TYPE_INIT_REQ);
        assertEquals(CMPRequestType.INITIALIZATION_REQUEST.toString(), requestMessage);
    }

    @Test
    public void testConvertRequestTypeToString_ForKUR() {
        String requestMessage = PKIMessageUtil.convertRequestTypeToString(PKIBody.TYPE_KEY_UPDATE_REQ);
        assertEquals(CMPRequestType.KEY_UPDATE_REQUEST.toString(), requestMessage);
    }

    @Test
    public void testConvertRequestTypeToString_ForCertConf() {
        String requestMessage = PKIMessageUtil.convertRequestTypeToString(PKIBody.TYPE_CERT_CONFIRM);
        assertEquals(CMPRequestType.CERTIFICATE_CONFIRMATION.toString(), requestMessage);
    }

    @Test
    public void testConvertRequestTypeToString_ForPollRequest() {
        String requestMessage = PKIMessageUtil.convertRequestTypeToString(PKIBody.TYPE_POLL_REQ);
        assertEquals(CMPRequestType.POLL_REQUEST.toString(), requestMessage);
    }

    @Test
    public void testConvertRequestTypeToString_ForErrorRequest() {
        String requestMessage = PKIMessageUtil.convertRequestTypeToString(PKIBody.TYPE_ERROR);
        assertEquals(CMPRequestType.INVALID_REQUEST.toString(), requestMessage);
    }
}
