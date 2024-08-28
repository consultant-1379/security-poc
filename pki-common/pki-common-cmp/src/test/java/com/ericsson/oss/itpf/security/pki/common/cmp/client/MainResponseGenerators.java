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

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class MainResponseGenerators extends AbstractMain {

    /**
     * This Method generates CMP initial response message.
     * 
     * @param args
     *            configuration parameters for initial request.
     * @param responseMessage
     *            the input message could be initial request message
     * @return initial response message.
     */
    public static PKIMessage generateInitialResponse(String[] args, PKIMessage responseMessage) throws Exception {

        PKIMessage message = null;

        Parameters parameters = getParams(args);
        CommonResponseGenerator messageGenerator = new CommonResponseGenerator(parameters);
        message = messageGenerator.generateResponse(responseMessage, PKIBody.TYPE_INIT_REP, false);

        return message;
    }
}
