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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.IPWithWaitResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(MockitoJUnitRunner.class)
public class FailureMessageBuilderTest {

    @InjectMocks
    FailureMessageBuilder failureMessageBuilder;

    @Mock
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Mock
    CMPMessageEntity cMPMsgEntity;

    @Mock
    PersistenceHandler persistenceHandler;
    
    @Mock
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Mock
    CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Mock
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    @Mock
    Logger logger;

    private static RequestMessage irRequestMessage;
    private static ResponseMessage ipResponseMessage;
    private static String senderName;
    private static String transactionID = null;
    public static final String SENDER = "CN=issuer";
    private static final String ISSUERNAME = "TestCA";

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage ipWaitingResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.IP_WITH_WAIT_RESPONSE).generate(pkiRequestMessage, responseParameters);

        irRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        irRequestMessage.setIssuerName(ISSUERNAME);
        ipResponseMessage = new IPWithWaitResponseMessage(ipWaitingResponseMessage.getEncoded());

        transactionID = irRequestMessage.getBase64TransactionID();
        senderName = irRequestMessage.getSenderName();

    }

    @Test
    public void testBuild() throws InvalidInitialConfigurationException, ProtectionEncodingException, ResponseSignerException, IOException {
        final String errorMessage = "Error Message";
        setUpTestData();

        final byte[] actualFailureBytes = failureMessageBuilder.build(irRequestMessage, errorMessage);

        assertActualExpected(actualFailureBytes);
    }

    private void assertActualExpected(final byte[] actualFailureBytes) {
        final FailureResponseMessage actualFailureResponseMessage = new FailureResponseMessage(actualFailureBytes);
        Assert.assertEquals(transactionID, actualFailureResponseMessage.getBase64TransactionID());
        Mockito.verify(responseMessageSigningHelper).getSenderFromSignerCert(ISSUERNAME);
    }

    private void setUpTestData() throws IOException {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(SENDER);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<ResponseMessage> anyObject())).thenReturn(ipResponseMessage.toByteArray());
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(cMPMsgEntity);
    }

}
