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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;

@RunWith(PowerMockRunner.class)
@PrepareForTest(AttachedSignatureXMLBuilder.class)
public class RequestSignerTest {

    @InjectMocks
    CMPRequestSigner requestSigner;

    @Mock
    X509Certificate certificate;

    @Mock
    InitialConfiguration initialConfiguration;

    @Mock
    CMPRequest cMPRequestToBeSigned;

    @Mock
    RevocationRequest revocationServiceRequest;

    private static RequestMessage pKIRequestMessage;
    private static String transactionId;
    private static PrivateKey signerKey;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionId = pKIRequestMessage.getBase64TransactionID();
    }

    @Test
    public void testGetCMPSignedXMLData() {

        byte[] cmpRequest = new byte[] { 1 };
        Mockito.when(initialConfiguration.getCertificateforEventSigning()).thenReturn(certificate);
        Mockito.when(initialConfiguration.getPrivateKeyForSigning()).thenReturn(signerKey);
        PowerMockito.mockStatic(AttachedSignatureXMLBuilder.class);
        Mockito.when(AttachedSignatureXMLBuilder.build(certificate, signerKey, cMPRequestToBeSigned)).thenReturn(cmpRequest);
        requestSigner.getCMPSignedXMLData(pKIRequestMessage, transactionId);
        Mockito.verify(initialConfiguration).getPrivateKeyForSigning();
    }

    @Test
    public void testSignRevocationRequest() {

        byte[] signedRevocationRequest = new byte[] { 1 };
        Mockito.when(initialConfiguration.getCertificateforEventSigning()).thenReturn(certificate);
        Mockito.when(initialConfiguration.getPrivateKeyForSigning()).thenReturn(signerKey);
        PowerMockito.mockStatic(AttachedSignatureXMLBuilder.class);
        Mockito.when(AttachedSignatureXMLBuilder.build(certificate, signerKey, revocationServiceRequest)).thenReturn(signedRevocationRequest);
        requestSigner.signRevocationRequest(revocationServiceRequest);
        Mockito.verify(initialConfiguration).getPrivateKeyForSigning();
    }
}
