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
public class PollRequestHandlerTest {

    @InjectMocks
    PollRequestHandler pollRequestHandler;

    @Mock
    TransactionIdHandler transactionIDHandler;

    private static RequestMessage pKIPollRequestMessage;
    private static String transactionID;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);

        final PKIMessage irmessage = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(requestParameters, pkiResponseMessage);
        pKIPollRequestMessage = new RequestMessage(irmessage.getEncoded());
        transactionID = pKIPollRequestMessage.getBase64TransactionID();
    }

    @Test
    public void testHandle() {

        Mockito.when(transactionIDHandler.handle(pKIPollRequestMessage, false)).thenReturn(transactionID);

        pollRequestHandler.handle(pKIPollRequestMessage);

        Mockito.verify(transactionIDHandler).handle(pKIPollRequestMessage, false);

    }

}
