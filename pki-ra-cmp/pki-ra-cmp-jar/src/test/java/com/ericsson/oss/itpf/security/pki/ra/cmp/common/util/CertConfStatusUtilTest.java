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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.util;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;

@RunWith(MockitoJUnitRunner.class)
public class CertConfStatusUtilTest {

    @InjectMocks
    CertConfStatusUtil certConfStatusUtil;

    private static RequestMessage pKICertConfRequestmessage;
    public static final String sender = "CN=issuer";
    static PKIMessage pkiRequestMessage;

    @BeforeClass
    public static void prepareCertConfRequestMessage() throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException, IOException {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        Parameters responseParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);

        PKIMessage pkiCertConfRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        pKICertConfRequestmessage = new RequestMessage(pkiCertConfRequestMessage.getEncoded());

    }

    @Test
    public void testGetMessageStatus() {
        MessageStatus certConfStatus = certConfStatusUtil.get(pKICertConfRequestmessage);
        Assert.assertEquals(MessageStatus.DONE, certConfStatus);
    }

}
