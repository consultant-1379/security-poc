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
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CMPRequestSigner;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.dispatcher.ProtocolServiceRequestDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.CMPServiceRequest;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

@RunWith(MockitoJUnitRunner.class)
public class InitializationRequestHandlerTest {

    @InjectMocks
    InitializationRequestHandler initializationRequestHandler;

    @Mock
    TransactionIdHandler transactionIDHandler;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    ProtocolServiceRequestDispatcher cMPServiceRequestdispatcher;

    @Mock
    CMPServiceRequest cMPServiceRequest;

    @Mock
    InitialConfiguration initialConfiguration;

    @Mock
    CMPRequestSigner requestSigner;

    @Mock
    private CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    private static RequestMessage pKIRequestMessage;
    private static String transactionId;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionId = pKIRequestMessage.getBase64TransactionID();
    }

    @Test
    public void testHandle() {

        byte[] signedXMLData = new byte[1];
        Mockito.when(transactionIDHandler.handle(pKIRequestMessage, true)).thenReturn(transactionId);
        Mockito.when(requestSigner.getCMPSignedXMLData(pKIRequestMessage, transactionId)).thenReturn(signedXMLData);
        initializationRequestHandler.handle(pKIRequestMessage);

        Mockito.verify(transactionIDHandler).handle(pKIRequestMessage, true);
        Mockito.verify(persistenceHandler).persist(pKIRequestMessage, transactionId);

    }

}
