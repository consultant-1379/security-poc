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

package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.ResponseHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.PKIManagerResponseProcessor;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.handler.PKIManagerCMPResponseHandler;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ JaxbUtil.class, CertificateUtility.class })
public class PKIManagerCMPResponseHandlerTest {

    @InjectMocks
    PKIManagerCMPResponseHandler pkiManagerCMPResponseHandler;

    @Mock
    PKIManagerResponseProcessor responseUtility;

    @Mock
    CMPResponse cMPResponseXMLData;

    @Mock
    CMPLocalService cmpLocalService;

    @Mock
    ResponseHandlerFactory responseHandlerFactory;

    @Mock
    ResponseHandler responseHandler;

    @Mock
    Logger logger;

    @Mock
    Document document;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    X509Certificate managerSignerCertificate;

    @Mock
    SignedCMPServiceResponse signedCMPServiceResponse;

    @Test
    public void testHandleForIP() throws CertificateException, IOException {

        final int responseType = 1;
        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(JaxbUtil.getObject(document, CMPResponse.class)).thenReturn(cMPResponseXMLData);
        Mockito.when(cMPResponseXMLData.getResponseType()).thenReturn(responseType);
        Mockito.when(responseHandlerFactory.getResponseHandler(cMPResponseXMLData)).thenReturn(responseHandler);

        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);
        Mockito.verify(responseHandlerFactory).getResponseHandler(cMPResponseXMLData);

    }

    @Test
    public void testHandleForInvalidInitialConfigurationException() {
        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenThrow(
                new InvalidInitialConfigurationException());
        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);
        Mockito.verify(responseUtility).loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());

    }

    @Test
    public void testHandleForXMLUtilityException() throws CertificateException, IOException {
        final int responseType = 1;
        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(JaxbUtil.getObject(document, CMPResponse.class)).thenReturn(cMPResponseXMLData);
        Mockito.when(cMPResponseXMLData.getResponseType()).thenReturn(responseType);
        Mockito.when(responseHandlerFactory.getResponseHandler(cMPResponseXMLData)).thenReturn(responseHandler);

        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);
        Mockito.verify(responseUtility).loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());

    }

    @Test
    public void testHandleForResponseHandlerException() throws CertificateException, IOException {
        final int responseType = 1;
        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenReturn(document);

        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(JaxbUtil.getObject(document, CMPResponse.class)).thenReturn(cMPResponseXMLData);
        Mockito.when(cMPResponseXMLData.getResponseType()).thenReturn(responseType);
        Mockito.doThrow(new ResponseHandlerException()).when(responseHandlerFactory).getResponseHandler(cMPResponseXMLData);
        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);

        Mockito.verify(responseUtility).loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());
    }

    @Test
    public void testHandleForResponseSignerException() throws CertificateException, IOException {
        final int responseType = 1;
        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenReturn(document);

        PowerMockito.mockStatic(JaxbUtil.class);

        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(JaxbUtil.getObject(document, CMPResponse.class)).thenReturn(cMPResponseXMLData);
        Mockito.when(cMPResponseXMLData.getResponseType()).thenReturn(responseType);
        Mockito.when(responseHandlerFactory.getResponseHandler(cMPResponseXMLData)).thenReturn(responseHandler);
        Mockito.when(responseHandler.handle(cMPResponseXMLData)).thenThrow(new ResponseSignerException());

        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);

        Mockito.verify(responseUtility).loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());

    }

    @Test
    public void testHandleForIPforSignatureException() {
        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenThrow(
                new DigitalSignatureValidationException());
        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);
        Mockito.verify(responseUtility).loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());

    }

    @Test
    public void testHandleForIPforInvalidInitialConfigurationException() {

        Mockito.when(responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse())).thenThrow(
                new InvalidInitialConfigurationException());
        pkiManagerCMPResponseHandler.handle(signedCMPServiceResponse);
        Mockito.verify(responseUtility).loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());

    }

}
