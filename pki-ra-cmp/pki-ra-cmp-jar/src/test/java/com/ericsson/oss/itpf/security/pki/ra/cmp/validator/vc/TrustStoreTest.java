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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidMessageException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.TrustStoreUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.BaseDigitalSignatureValidatorTestUtil;

@RunWith(MockitoJUnitRunner.class)
public class TrustStoreTest {

    @InjectMocks
    TrustStoreUtil trustStore;

    @Mock
    InitialConfiguration configurationData;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    CMPMessageEntity cMPMessageEntity;

    @Mock
    Logger logger;

    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKIInvalidRequestType;
    private static RequestMessage pKIPollRequestMessage;
    private static RequestMessage pKIKeyUpdateRequestMessage;
    private static RequestMessage pKICertConfRequestmessage;

    private static Set<X509Certificate> vendorCertificateSet = null;

    @BeforeClass
    public static void prepareTestData() throws IOException {

        Parameters parameters = AbstractMain.configureParameters(null);

        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        parameters = AbstractMain.configureParameters(null);
        final PKIMessage responseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.IP_WITH_WAIT_RESPONSE).generate(pkiRequestMessage, parameters);
        parameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, parameters);

        final PKIMessage pkiPollRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(parameters, responseMessage);
        final PKIMessage pkiKURMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(parameters, null);
        final PKIMessage pkiCertConfMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(parameters, pkiResponseMessage);

        parameters.setValidRequestType(false);
        final PKIMessage pkiInvalidRequestType = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);

        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIInvalidRequestType = new RequestMessage(pkiInvalidRequestType.getEncoded());
        pKIPollRequestMessage = new RequestMessage(pkiPollRequestMessage.getEncoded());
        pKIKeyUpdateRequestMessage = new RequestMessage(pkiKURMessage.getEncoded());
        pKICertConfRequestmessage = new RequestMessage(pkiCertConfMessage.getEncoded());

        vendorCertificateSet = BaseDigitalSignatureValidatorTestUtil.getVendorCerts();

    }

    @Test
    public void testGetTrustedCertsBasedOnRequestTypeForIR() throws Exception {

        Mockito.when(configurationData.getVendorCertificateSet()).thenReturn(vendorCertificateSet);
        trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        Mockito.verify(configurationData).getVendorCertificateSet();

    }

    @Test
    public void testGetTrustedCertsBasedOnRequestTypeForKUR() throws Exception {

        Mockito.when(configurationData.getCaCertificateSet()).thenReturn(vendorCertificateSet);
        trustStore.getTrustedCertsBasedOnRequestType(pKIKeyUpdateRequestMessage);
        Mockito.verify(configurationData).getCaCertificateSet();
    }

    @Test(expected = InvalidMessageException.class)
    public void testGetTrustedCertConfException() throws Exception {

        Mockito.when(configurationData.getCaCertificateSet()).thenReturn(vendorCertificateSet);
        trustStore.getTrustedCertsBasedOnRequestType(pKICertConfRequestmessage);
        Mockito.verify(configurationData).getCaCertificateSet();
    }

    @Test(expected = InvalidMessageException.class)
    public void testGetTrustedCertsBasedOnRequestTypeForDefault() throws Exception {
        trustStore.getTrustedCertsBasedOnRequestType(pKIInvalidRequestType);
    }

    @Test
    public void testValidateForPollRequest() throws Exception {
        CMPMessageEntity entity = null;

        final int requestType = pKIRequestMessage.getRequestType();
        final String transactionId = pKIPollRequestMessage.getBase64TransactionID();
        final String sender = pKIPollRequestMessage.getSenderName();

        entity = new CMPMessageEntity();
        entity.setInitialMessage(pKIRequestMessage.toByteArray());

        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, sender)).thenReturn(entity);
        Mockito.when(configurationData.getTrustedCerts(requestType)).thenReturn(vendorCertificateSet);

        trustStore.getTrustedCertsBasedOnRequestType(pKIPollRequestMessage);
        Mockito.verify(configurationData).getTrustedCerts(requestType);

    }

    @Test(expected = InvalidMessageException.class)
    public void testDigitalSignatureValidationExceptionForValidate() throws Exception {

        trustStore.getTrustedCertsBasedOnRequestType(pKIInvalidRequestType);
    }

    @Test(expected = MessageParsingException.class)
    public void testIOException() throws Exception {

        final byte[] invalidByteArray = new byte[] { (byte) 257, (byte) 655, (byte) 333 };
        final String transactionId = pKIPollRequestMessage.getBase64TransactionID();
        final String sender = pKIPollRequestMessage.getSenderName();

        final CMPMessageEntity entity = new CMPMessageEntity();
        entity.setInitialMessage(invalidByteArray);

        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, sender)).thenReturn(entity);
        trustStore.getTrustedCertsBasedOnRequestType(pKIPollRequestMessage);

    }

}
