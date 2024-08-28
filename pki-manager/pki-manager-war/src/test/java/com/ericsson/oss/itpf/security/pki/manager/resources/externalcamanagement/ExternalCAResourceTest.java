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

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.MockDispatcherFactory;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.helper.CRLDownloader;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

@RunWith(MockitoJUnitRunner.class)
public class ExternalCAResourceTest {

    @InjectMocks
    private ExternalCAResource externalCAResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(ExternalCAResource.class);

    @Mock
    private ExtCACRLManagementService extCACRLManagementService;

    @Mock
    private ExtCACertificateManagementService extCaCertificateManagementService;

    @Mock
    CRLDownloader crlDownloader;

    @Mock
    PKIManagerEServiceProxy pkiManagerEServiceProxy;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    @Before
    public void setup() throws IOException {

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(externalCAResource);
        response = new MockHttpResponse();
        Mockito.when(pkiManagerEServiceProxy.getExtCaCertificateManagementService()).thenReturn(extCaCertificateManagementService); 
        Mockito.when(pkiManagerEServiceProxy.getExtCACRLManagementService()).thenReturn(extCACRLManagementService); 

    }

    @Test(expected = Exception.class)
    public void testUpdateByUrlNotFound() throws Exception {

        request = MockHttpRequest.put("/extca/update/url/MyExtCA");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content("http:localhost/MyUrl".getBytes("UTF-8"));
        dispatcher.invoke(request, response);
    }

    @Test
    public void testUpdateByFile() throws Exception {
        Mockito.doNothing().when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/update/crlfile/MyExtCA");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.OK.getStatusCode(), response.getStatus());
    }

    @Test
    public void testUpdateMissingMandatoryFieldException() throws Exception {
        Mockito.doThrow(MissingMandatoryFieldException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/update/crlfile/MyExtCA");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testUpdateExternalCRLException() throws Exception {
        Mockito.doThrow(ExternalCRLException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/update/crlfile/MyExtCA");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testUpdateExternalCANotFoundException() throws Exception {
        Mockito.doThrow(ExternalCANotFoundException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/update/crlfile/MyExtCA");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testUpdateExternalCredentialMgmtServiceException() throws Exception {
        Mockito.doThrow(ExternalCredentialMgmtServiceException.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/update/crlfile/MyExtCA");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testUpdateException() throws Exception {
        Mockito.doThrow(Exception.class).when(this.extCACRLManagementService).addExternalCRLInfo(any(String.class), any(ExternalCRLInfo.class));
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/update/crlfile/MyExtCA");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testImport() throws Exception {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("certificates/certificateENM_PKI_Root_CA.pem");
        request = MockHttpRequest.put("/extca/import/MyExtCA/false");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        Mockito.doNothing().when(this.extCaCertificateManagementService).importCertificate(any(String.class), any(X509Certificate.class), any(Boolean.class));
        assertEquals(Status.OK.getStatusCode(), response.getStatus());
    }

    @Test
    public void testImportWithoutInputStream() throws Exception {
        final InputStream inputStream = null;
        request = MockHttpRequest.put("/extca/import/MyExtCA/false");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testImportWithGetCertificateNull() throws Exception {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("crls/testCA.crl");
        request = MockHttpRequest.put("/extca/import/MyExtCA/false");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);

        Mockito.doNothing().when(this.extCaCertificateManagementService).importCertificate(any(String.class), any(X509Certificate.class), any(Boolean.class));
        assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testImportPEMWithMultipleCertificates() throws Exception {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("certificates/base64keystorewith2certs.pem");
        request = MockHttpRequest.put("/extca/import/MyExtCA/false");
        request.contentType(MediaType.APPLICATION_OCTET_STREAM);
        request.content(inputStream);
        dispatcher.invoke(request, response);
        Mockito.doNothing().when(this.extCaCertificateManagementService).importCertificate(any(String.class), any(X509Certificate.class), any(Boolean.class));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

}
