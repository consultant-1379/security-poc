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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;

@RunWith(MockitoJUnitRunner.class)
public class CertConfRequestHandlerTest {

    @InjectMocks
    CertConfRequestHandler certConfRequestHandler;

    @Mock
    TransactionIdHandler transactionIDHandler;

    private static RequestMessage pKICertConfRequestmessage;
    private static String transactionId;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);
        final PKIMessage pkiCertConfMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        pKICertConfRequestmessage = new RequestMessage(pkiCertConfMessage.getEncoded());
        transactionId = pKICertConfRequestmessage.getBase64TransactionID();
    }

    @Test
    public void testHandle() {
        final boolean tobeGenerated = false;
        Mockito.when(transactionIDHandler.handle(pKICertConfRequestmessage, tobeGenerated)).thenReturn(transactionId);
        certConfRequestHandler.handle(pKICertConfRequestmessage);
        Mockito.verify(transactionIDHandler).handle(pKICertConfRequestmessage, tobeGenerated);
    }

}
