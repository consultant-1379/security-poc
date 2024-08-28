/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.handler;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ErrorResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.CertResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.instrumentation.SCEPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;
import com.ericsson.oss.itpf.security.pki.ra.scep.processor.*;

/**
 * This class contains the test for PkiOperationHandler
 */
@RunWith(MockitoJUnitRunner.class)
public class PkiOperationHandlerTest {

    @Mock
    private Logger logger;

    @InjectMocks
    private PkiOperationHandler pkiOperationHandler;

    @Mock
    private PkiScepResponse pkiScepResponse;
    @Mock
    private PkiOperationReqProcessor pkiOperReqProcessor;
    @Mock
    private GetCertInitProcessor getCertInitProcessor;
    @Mock
    private PkcsRequestProcessor pkcsRequestProcessor;
    @Mock
    private CertResponseBuilder certResponseBuilder;
    @Mock
    private Pkcs7ScepRequestData pkcs7ScepRequestData;
    @Mock
    private Pkcs7ScepResponseData pkcs7ScepResponseData;
    @Mock
    private Pkcs7ScepRequestEntity pkcs7ScepRequestEntity;

    @Mock
    private SystemRecorder systemRecorder;
    
    @Mock
    SCEPInstrumentationBean scepInstrumentationBean;

    private PkiScepRequest pkiScepRequest;

    private String certInitial = "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";

    private String pendingpkcs = "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";

    private String getCrl = "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";

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @Before
    public void setup() {
        pkiScepRequest = new PkiScepRequest();
    }

    /**
     * This method tests certInitial request Message
     */
    @Test
    public void testCertInitialHandle() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(0);
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
        Mockito.verify(logger).debug("End of Handle method in PkiOperationHandler class");
    }

    /**
     * This method tests certInitial request Message with pending
     */
    @Test
    public void testCertInitialHandlePending() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(3);
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
        Mockito.verify(logger).debug("End of Handle method in PkiOperationHandler class");
    }

    /**
     * This method tests certInitial Unauthorized Request Message.
     */
    @Test(expected = UnauthorizedException.class)
    public void testUnauthorizedRequest() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.UNAUTHORIZED.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when ENTITY_NOT_FOUND.
     */
    @Test(expected = UnauthorizedException.class)
    public void testEntityNotFound() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.ENTITY_NOT_FOUND.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when INVALID_ENTITY.
     */
    @Test(expected = UnauthorizedException.class)
    public void testInvalidEntity() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.INVALID_ENTITY.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when INVALID_OTP.
     */
    @Test(expected = UnauthorizedException.class)
    public void testInvalidOtp() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.INVALID_OTP.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when OTP_EXPIRED
     */
    @Test(expected = UnauthorizedException.class)
    public void testOtpExpired() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.OTP_EXPIRED.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when OTP_NOT_FOUND
     */
    @Test(expected = BadRequestException.class)
    public void testOtpNotFound() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.OTP_NOT_FOUND.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when CERTIFICATE_EXISTS
     */
    @Test(expected = PkiScepServiceException.class)
    public void testCertificateExists() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.CERTIFICATE_EXISTS.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when INTERNAL_ERROR
     */

    @Test(expected = PkiScepServiceException.class)
    public void testInternalError() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.INTERNAL_ERROR.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial when BAD_REQUEST
     */
    @Test(expected = BadRequestException.class)
    public void testCertIntialFailureHandle() {
        pkiScepRequest.setMessage(certInitial.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(20);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(pkcs7ScepRequestEntity.getFailInfo()).thenReturn(ErrorResponse.BAD_REQUEST.getValue());
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests PkcsRequestHandle
     */
    @Test
    public void testPkcsRequestHandle() {
        pkiScepRequest.setMessage(pendingpkcs.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(19);
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial with UnSupportedMsgType
     */
    @Test(expected = UnSupportedMsgTypeException.class)
    public void testInvalidMsgType() {
        pkiScepRequest.setMessage(pendingpkcs.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(3);
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }

    /**
     * This method tests certInitial with wrong msg type
     */
    @Test(expected = NotImplementedMsgTypeException.class)
    public void testGetCrl() {
        pkiScepRequest.setMessage(getCrl.getBytes());
        Mockito.when(pkcs7ScepRequestData.getMessageType()).thenReturn(22);
        Mockito.when(pkcs7ScepRequestEntity.getStatus()).thenReturn(2);
        Mockito.when(getCertInitProcessor.processRequest(pkcs7ScepRequestData)).thenReturn(pkcs7ScepRequestEntity);
        pkiOperationHandler.handle(pkiScepRequest);
    }
}
