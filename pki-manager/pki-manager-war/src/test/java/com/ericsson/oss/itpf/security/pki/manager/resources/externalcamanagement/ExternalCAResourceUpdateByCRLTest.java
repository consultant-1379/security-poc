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
package com.ericsson.oss.itpf.security.pki.manager.resources.externalcamanagement;

import static org.mockito.Matchers.any;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import javax.ws.rs.core.MediaType;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.helper.CRLDownloader;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CRLDownloader.class)
public class ExternalCAResourceUpdateByCRLTest {

    @InjectMocks
    private ExternalCAResource externalCAResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(ExternalCAResource.class);

    @Mock
    private ExtCACRLManagementService extCACRLManagementService;

    @Mock
    private ExtCACertificateManagementService extCaCertificateManagementService;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    @Before
    public void setup() throws IOException {

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(externalCAResource);
        response = new MockHttpResponse();
    }

    @Test
    public void testUpdateByUrl() throws Exception {

        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        final URL url = new URL("http:localhost/MyUrl");
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(url)).thenReturn(x509crl);
        Mockito.doNothing().when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }

    @Test
    public void testUpdateByUrlException() throws Exception {

        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        final URL url = new URL("http:localhost/MyUrl");
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(url)).thenReturn(x509crl);
        Mockito.doThrow(Exception.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }

    @Test
    public void testUpdateByUrlExternalCRLException() throws Exception {

        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        final URL url = new URL("http:localhost/MyUrl");
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(url)).thenReturn(x509crl);
        Mockito.doThrow(ExternalCRLException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }

    @Test
    public void testUpdateByUrlExternalCANotFoundException() throws Exception {

        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        final URL url = new URL("http:localhost/MyUrl");
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(url)).thenReturn(x509crl);
        Mockito.doThrow(ExternalCANotFoundException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }

    @Test
    public void testUpdateByUrlExternalCredentialMgmtServiceException() throws Exception {

        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        final URL url = new URL("http:localhost/MyUrl");
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(url)).thenReturn(x509crl);
        Mockito.doThrow(ExternalCredentialMgmtServiceException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }

    @Test
    public void testUpdateByUrlMissingMandatoryFieldException() throws Exception {

        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        final URL url = new URL("http:localhost/MyUrl");
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(url)).thenReturn(x509crl);
        Mockito.doThrow(MissingMandatoryFieldException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }
}
