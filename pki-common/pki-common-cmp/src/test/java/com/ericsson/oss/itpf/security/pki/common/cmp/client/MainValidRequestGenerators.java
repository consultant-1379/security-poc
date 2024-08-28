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
package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import java.security.Security;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class MainValidRequestGenerators extends AbstractMain {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * This Method generates CMP initial request message.
     * 
     * @param args
     *            configuration parameters for initial request.
     * @return initial request message
     */
    public static PKIMessage generateInitialRequest(String[] args) throws Exception {
        PKIMessage message = null;
        Parameters parameters = getParams(args);
        InitialOrKeyUpdateRequestGenerator messageGenerator = new InitialOrKeyUpdateRequestGenerator(parameters);
        message = messageGenerator.generateIRorKUR(PKIBody.TYPE_INIT_REQ);

        return message;
    }

    /**
     * This Method generates CMP poll request message.
     * 
     * @param args
     *            configuration parameters for initial request.
     * @param responseMessage
     *            the input message could be initial response/key update response/poll response
     * @return poll request message
     */
    public static PKIMessage generatePollRequest(String[] args, PKIMessage responseMessage) throws Exception {

        PKIMessage message = null;
        Parameters parameters = getParams(args);
        PollRequestGenerator messageGenerator = new PollRequestGenerator(parameters);
        message = messageGenerator.generatePollReq(responseMessage);

        return message;
    }
}
