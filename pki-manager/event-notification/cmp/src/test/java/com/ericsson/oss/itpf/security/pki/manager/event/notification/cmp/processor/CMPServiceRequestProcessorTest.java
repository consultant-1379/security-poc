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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.processor;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.*;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.RequestHandlerUtility;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.SignedResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceRequest;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ JaxbUtil.class, CertificateUtility.class })
public class CMPServiceRequestProcessorTest {

    @InjectMocks
    CMPServiceRequestProcessor cMPServiceRequestProcessor;

    @Mock
    SignedCMPServiceRequest cMPServiceRequest;

    @Mock
    SignedResponseBuilder signedResponseBuilder;

    @Mock
    RequestHandlerUtility requestHandlerUtility;

    @Mock
    RequestHandlerFactory protocolRequestHandlerFactory;

    @Mock
    RequestHandler requestHandler;

    @Mock
    X509Certificate requestSignerCertificate;

    @Mock
    Logger logger;

    @Mock
    Certificate certificateToValidate;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    CertificateManagementLocalService certificateManagementLocalService;

    @Mock
    SystemRecorder systemRecorder;

    private Document document;

    @Before
    public void setup() {
        final String cmpRequestString = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PGNtcFJlcXVlc3Q+PGNtcFJlcXVlc3Q+QVE9PTwvY21wUmVxdWVzdD48cmVxdWVzdFR5cGU+MDwvcmVxdWVzdFR5cGU+PHN5bmNSZXF1ZXN0PnRydWU8L3N5bmNSZXF1ZXN0Pjx0cmFuc2FjdGlvbklkPjEyMzQ8L3RyYW5zYWN0aW9uSWQ+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8yMDAxL1JFQy14bWwtYzE0bi0yMDAxMDMxNSIvPjxTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PFJlZmVyZW5jZSBVUkk9IiI+PFRyYW5zZm9ybXM+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+dTdPUUJzTGZsVFpadnJyOG42czJPNm94VThrOWsrNWgvNHIxTmo0NVQ4QT08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+a0EwL1lzOUJNR1J3eU1rWStzSHRLQm5iZGRmSTB0c0FNbkJEMU5ERWZ4V0VGVWNlaC9yYy9BdjlUUXpLY0pQdFAra0p3Q0JVNjA2Yg0Kc05lU2ZxZXc4bDRYY0xTcW14L0lCN2NIQ0JjWS8wdDBJQzhhc2JFSGpvNTRjdGYxUjNjMldzNFNPN0Z2dHBtbEdmeW55azM0TXd3Uw0KeTJuNEZ2cGdEaStibUNiejRZYTF3ZFJLOXlsblg1elNJQkFIR3d0NGZjV3pvOU9nbkp5VG10R0xHak9pc0Rlckhyd1VmTkRYRFpRVQ0KbVlnbnJmdEMxcWIvajY0SHQ3QktnVmpIOXVYS1pTSmxwblg5dG9kdXIwRkpFSkhJZGZXcVp6RCthYnpQVFZCcjZYSlZib3k0b1lxdg0KbVhOdWhZb3RnVE1TdmFpZlYyRFJ2SExHelRtbHpFM25tNEN6akE9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRCtUQ0NBdUdnQXdJQkFnSUVKRzIxRURBTkJna3Foa2lHOXcwQkFRVUZBREF4TVJFd0R3WURWUVFLREFoRmNtbGpjM052YmpFYw0KTUJvR0ExVUVBd3dUVEZSRlNWQlRaV05PUldOMWMxSnZiM1JEUVRBZUZ3MHhOREV4TURVd05qSTVNamRhRncweE9URXhNRE14TWpJNQ0KTWpGYU1DNHhMREFxQmdOVkJBTU1JMHhVUlVsUVUyVmpUa1ZqZFhOaGRHTnNkbTB4TURJMFUyTmxjRkpoVTJWeWRtVnlNSUlCSWpBTg0KQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcHV1QUdabXZzVjladmxYeW15QzZPVC9nL3h5L25MVURPTE5nOCs1YQ0KUHo2VlMvR3lIT2FsYlcraHJ4d1JRZjJSU0ROUHJoWjFMcXZtaHQxSk9HVnlBRUdHQTRyS1c4NXdhQXFsKzZrRThJNlhGNS9YYnhLOQ0KeDN0NzFienBXVkZVb0JNYTZDMUE0TGJPREw2bnBMNjhSaXVRQityOEsyZXAzSFdTNm42ZWVXNlEyWXVVNG1LL0RRaXhVc3RqdG1wSQ0KWkdRbWVqZkdIb0hrS2E5dkRqeEpYeXp0RTlkUHZSZUZMVFV2TXFvckpwc0RHVzNPREUvRWFNY0FrRjBneVIvcmRFUFNUWUtEd1NwRw0KV3dtOXgxVzFSRE5KZ2tjdjh3ejZDWHhhd2lIb2FpWmJBVUdnTWdtT2VOWEZMNTZUMG56c3ZiNm82WTlMNHo5ZDB2Z2NKUk9vMHdJRA0KQVFBQm80SUJHakNDQVJZd0hRWURWUjBPQkJZRUZQaVNMLzNlWTk1clBhQUk2T1lvTVk5QXRGYWVNQXdHQTFVZEV3RUIvd1FDTUFBdw0KSHdZRFZSMGpCQmd3Rm9BVWt1ZU9KUEl3M1M4L2RZZmllV2NzaEVXS0R6Z3dnYlVHQTFVZEh3U0JyVENCcWpCVG9GR2dUNFpOYUhSMA0KY0RvdkwyTmtjREV1WTJSd2N5NWhkR2gwWlcwdVpXVnBMbVZ5YVdOemMyOXVMbk5sT2pJek56Y3ZhVzUwWlhKdVlXd3ZURlJGU1ZCVA0KWldOT1JXTjFjMUp2YjNSRFFTNWpjbXd3VTZCUm9FK0dUV2gwZEhBNkx5OWpaSEF5TG1Oa2NITXVZWFJvZEdWdExtVmxhUzVsY21sag0KYzNOdmJpNXpaVG95TXpjM0wybHVkR1Z5Ym1Gc0wweFVSVWxRVTJWalRrVmpkWE5TYjI5MFEwRXVZM0pzTUE0R0ExVWREd0VCL3dRRQ0KQXdJRHFEQU5CZ2txaGtpRzl3MEJBUVVGQUFPQ0FRRUFPNDBjNUJUSlpMOWZRWHFnYmpXR2ZOOUtha1YrVCtXamFvY3JVRzZjSzA0Wg0KSHRqM3gxY2t0ZEkvNzdMbXNJOXhwdU9LUWZWbU1lMEpnaFk5cUJsU28wVzJNNkxVeXBzRGFwQUFZU0ZmaDg4ZHR3R09Ha2xrU29HSw0KREJPRDNkcXVNMDIvdnFqZmZhN0MzWXUvekJINTJwekcraDhTeUVSZ21Wb3RLNnBPbC95UjZxeEYycUJ4dWsraTNoU3NqQlV1QTFSSw0KY2VoUVFudTFBZzBSY3BHem5BSDRCbzgycFg4WW1QdzRYWHdWaXNwdDdMbkw2ZlYzSjkydEdENEl6UnNuOUpFQ1hFakZHbUZSa3NiQg0KOEV3RWNxRVhKSUNIT2MyY1AxUktOVndwUVpDdExaVWNMRjlNWE5DRUpPajRQbHA2L0lINHZhdHhkVllwTUdvK0JGNkJnUT09PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PC9jbXBSZXF1ZXN0Pg==";
        byte[] cmpRequestArray = cmpRequestString.getBytes();
        if (StringUtility.isBase64(new String(cmpRequestArray))) {
            cmpRequestArray = Base64.decode(cmpRequestArray);
        }
        cMPServiceRequest.setCmpRequest(cmpRequestArray);
        document = DOMUtil.getDocument(cmpRequestArray);
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(cMPServiceRequest.getCmpRequest())).thenReturn(document);
        Mockito.when(protocolRequestHandlerFactory.getRequestHandler(Mockito.any(CMPRequest.class))).thenReturn(requestHandler);
        PowerMockito.mockStatic(JaxbUtil.class);
    }

    @Test
    public void testProcessRequest() {
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
    }

    @Test
    public void testProcessRequestUnmarshalException() {
        Mockito.when((CMPRequest) JaxbUtil.getObject(document, CMPRequest.class)).thenThrow(new UnmarshalException("UnmarshalException"));
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("ERROR OCCURED WHILE PARSING RESPONSE XML");
    }

    @Test
    public void testProcessRequestMarshalException() {

        Mockito.when((CMPRequest) JaxbUtil.getObject(document, CMPRequest.class)).thenThrow(new MarshalException("MarshalException"));
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("ERROR OCCURED WHILE MARSHALING DATA TO XML");
    }

    @Test
    public void testProcessRequestCredentialsManagementServiceException() {

        Mockito.when((CMPRequest) JaxbUtil.getObject(document, CMPRequest.class)).thenThrow(new CredentialsManagementServiceException("UnmarshalException"));
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("INTERNAL ERROR OCCURED IN CREDENTIAL MANAGEMENT");
    }

    @Test
    public void testProcessRequestInvalInitialExc() {
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(cMPServiceRequest.getCmpRequest())).thenThrow(new CredentialsManagementServiceException());
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("INTERNAL ERROR OCCURED IN CREDENTIAL MANAGEMENT");
    }

    @Test
    public void testProcessRequestDigitalSignatureValidationException() {
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(cMPServiceRequest.getCmpRequest())).thenThrow(new DigitalSignatureValidationException());
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("INVALID SIGNATURE ON THE RESPONSE MESSAGE DURING INITIAL ENROLLMENT");
    }

    @Test
    public void testProcessRequestDigitalSigningFailedException() {
        Mockito.when((CMPRequest) JaxbUtil.getObject(document, CMPRequest.class)).thenThrow(new DigitalSigningFailedException("DigitalSigningFailedException"));
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("FAILURE WHILE SIGNING CMPV2 PROTOCOL MESSAGES BY RA DURING INITIAl ENROLLMENT");
    }

    @Test
    public void testProcessRequestCertificateException() throws CertificateException, IOException {
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenThrow(new CertificateException("CertificateException"));
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("ERROR OCCURED WHILE FETCHING CERTIFICATE FROM CERTIFICATE HOLDER");
    }

    @Test
    public void testProcessRequestIOException() throws CertificateException, IOException {
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenThrow(new IOException("IOException"));
        cMPServiceRequestProcessor.processRequest(cMPServiceRequest);
        Mockito.verify(logger).error("ERROR OCCURED WHILE PERFORMING I/O OPERATIONS");
    }
}
