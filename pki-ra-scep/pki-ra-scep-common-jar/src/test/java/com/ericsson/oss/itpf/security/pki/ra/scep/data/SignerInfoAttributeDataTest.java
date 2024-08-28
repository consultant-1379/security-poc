package com.ericsson.oss.itpf.security.pki.ra.scep.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.FailureInfo;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.SignerInfoAttributeData;

@RunWith(MockitoJUnitRunner.class)
public class SignerInfoAttributeDataTest {

    @InjectMocks
    SignerInfoAttributeData signerInfoAttributeData;

    private String transactionId;
    private ResponseStatus status;
    private byte[] recipientNonce;
    private FailureInfo failInfo;
    private String digestAlgorithm;

    @Before
    public void setUp() throws Exception {

        transactionId = "33D29237707C1B0B937D563EE093BA1EDF981D3A";
        status = ResponseStatus.SUCCESS;
        failInfo = FailureInfo.BADREQUEST;
        digestAlgorithm = "1.3.14.3.2.26";
        recipientNonce = "recipientNonce".getBytes();

        signerInfoAttributeData = new SignerInfoAttributeData();
    }

    @Test
    public void testTransactionId_setTransactionId_getTransactionId() {

        signerInfoAttributeData.setTransactionId(transactionId);
        String transactionIdReturn = signerInfoAttributeData.getTransactionId();

        assertNotNull(transactionIdReturn);
        assertEquals(transactionId.hashCode(), transactionIdReturn.hashCode());
    }

    @Test
    public void testStatus_setStatus_getStatus() {

        signerInfoAttributeData.setStatus(status);
        ResponseStatus statusReturn = signerInfoAttributeData.getStatus();

        assertNotNull(statusReturn);
        assertEquals(status.hashCode(), statusReturn.hashCode());

    }

    @Test
    public void testRecipientNonce_setRecipientNonce_getRecipientNonce() {

        signerInfoAttributeData.setRecipientNonce(recipientNonce);
        byte[] recipientNonceReturn = signerInfoAttributeData.getRecipientNonce();

        assertNotNull(recipientNonceReturn);
        assertEquals(recipientNonce.hashCode(), recipientNonceReturn.hashCode());
    }

    @Test
    public void testFailInfo_setFailInfo_getFailInfo() {

        signerInfoAttributeData.setFailInfo(failInfo);
        FailureInfo failInfoReturn = signerInfoAttributeData.getFailInfo();

        assertNotNull(failInfoReturn);
        assertEquals(failInfo.hashCode(), failInfoReturn.hashCode());
    }

    @Test
    public void testDigestAlgorithm_setDigestAlgorithm_getDigestAlgorithm() {

        signerInfoAttributeData.setDigestAlgorithm(digestAlgorithm);
        String digestAlgorithmReturn = signerInfoAttributeData.getDigestAlgorithm();

        assertNotNull(digestAlgorithmReturn);
        assertEquals(digestAlgorithm.hashCode(), digestAlgorithmReturn.hashCode());

    }

}
