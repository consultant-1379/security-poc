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

package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.UnsupportedAlgorithmException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.SupportedAlgorithmsCacheWrapper;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmValidatorTest {
    @InjectMocks
    AlgorithmValidator algorithmValidator;

    @Mock
    SupportedAlgorithmsCacheWrapper supportedAlgorithmsCacheWrapper;

    @Mock
    Logger logger;

    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKIRequestMessageWithNullOid;
    private static RequestMessage pKIRequestMessageWithNotSupportedAlgoID;
    private static List<String> listOfAlgOid;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage =
                RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        requestParameters.setNullProtectionAlgorithm(true);
        final PKIMessage pkiRequestMessageWithNullProtectionAlgo =
                RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        final Parameters requestParameters1 = AbstractMain.configureParameters(null);
        requestParameters1.setValidProtectionAlgo(false);
        final PKIMessage pkiRequestMessageWithNotSupportedProtectionAlgo =
                RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters1, null);

        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIRequestMessageWithNullOid = new RequestMessage(pkiRequestMessageWithNullProtectionAlgo.getEncoded());
        pKIRequestMessageWithNotSupportedAlgoID = new RequestMessage(pkiRequestMessageWithNotSupportedProtectionAlgo.getEncoded());

        listOfAlgOid = new ArrayList<String>();
        listOfAlgOid.add("1.2.840.113549.1.1.5");
    }

    @Test
    public void testValidate() {
        Mockito.when(supportedAlgorithmsCacheWrapper.get(AlgorithmType.SIGNATURE_ALGORITHM.value())).thenReturn(listOfAlgOid);
        algorithmValidator.validate(pKIRequestMessage);
        Mockito.verify(supportedAlgorithmsCacheWrapper).get(AlgorithmType.SIGNATURE_ALGORITHM.value());
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void testNullProtectionOID() {
        algorithmValidator.validate(pKIRequestMessageWithNullOid);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void testNullCache() {
        Mockito.when(supportedAlgorithmsCacheWrapper.get(AlgorithmType.SIGNATURE_ALGORITHM.value())).thenReturn(null);
        algorithmValidator.validate(pKIRequestMessage);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void testForUnsupportedAlgo() {
        Mockito.when(supportedAlgorithmsCacheWrapper.get(AlgorithmType.SIGNATURE_ALGORITHM.value())).thenReturn(listOfAlgOid);
        algorithmValidator.validate(pKIRequestMessageWithNotSupportedAlgoID);
    }

}
