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

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.BodyValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.HeaderValidationException;

@RunWith(PowerMockRunner.class)
public class HeaderBodyValidatorTest {

    @InjectMocks
    PKIHeaderBodyValidator headerBodyValidator;

    @Mock
    Logger logger;

    private static RequestMessage pKIRequestMessageWithInvalidHeader;
    private static RequestMessage pKIRequestMessageWithInvalidTag;
    private static RequestMessage pKINotSupportedReqMessage;
    private static RequestMessage pKIRequestMessage;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters parameters = AbstractMain.configureParameters(null);

        final Parameters parameters1 = AbstractMain.configureParameters(null);
        parameters1.setValidHeader(false);
        final PKIMessage pkiReqMessageWithInvalidHeader = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters1, null);

        parameters.setInDirectoryFormat(false);
        final PKIMessage pkiReqMessageWithInvalidTag = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);

        final Parameters parameters2 = AbstractMain.configureParameters(null);
        parameters2.setValidRequestType(false);
        final PKIMessage pkiNotSupportedReqMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters2, null);
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIRequestMessageWithInvalidHeader = new RequestMessage(pkiReqMessageWithInvalidHeader.getEncoded());
        pKIRequestMessageWithInvalidTag = new RequestMessage(pkiReqMessageWithInvalidTag.getEncoded());
        pKINotSupportedReqMessage = new RequestMessage(pkiNotSupportedReqMessage.getEncoded());

    }

    @Test
    public void testValidate() {
        headerBodyValidator.validate(pKIRequestMessage);
        Mockito.verify(logger).info("Validated Header/Body for : {}", pKIRequestMessage.getRequestMessage());
    }

    @Test(expected = HeaderValidationException.class)
    public void testInvalidHeader() throws Exception {
        headerBodyValidator.validate(pKIRequestMessageWithInvalidHeader);

    }

    @Test(expected = HeaderValidationException.class)
    public void testInvalidTag() throws Exception {
        headerBodyValidator.validate(pKIRequestMessageWithInvalidTag);

    }

    @Test(expected = BodyValidationException.class)
    public void testInvalidRequest() throws Exception {
        headerBodyValidator.validate(pKINotSupportedReqMessage);

    }

}
