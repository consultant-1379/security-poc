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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.util;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;

@RunWith(PowerMockRunner.class)
@PrepareForTest(DOMUtil.class)
public class ResponseProcessorTest {

    @InjectMocks
    PKIManagerResponseProcessor responseProcessor;

    @Mock
    Document document;

    @Mock
    InitialConfiguration initialConfiguration;

    @Mock
    Set<X509Certificate> trustCertificates;

    @Mock
    DigitalSignatureValidator xmlDigitalSignatureValidator;

    @Test
    public void testGet() {
        byte[] signedXMLData = new byte[] { 1 };
        PowerMockito.mockStatic(DOMUtil.class);
        Mockito.when(DOMUtil.getDocument(signedXMLData)).thenReturn(document);
        Mockito.when(initialConfiguration.getCaCertificateSet()).thenReturn(trustCertificates);
        responseProcessor.loadAndValidateResponse(signedXMLData);
        Mockito.verify(initialConfiguration).getCaCertificateSet();
    }
}
