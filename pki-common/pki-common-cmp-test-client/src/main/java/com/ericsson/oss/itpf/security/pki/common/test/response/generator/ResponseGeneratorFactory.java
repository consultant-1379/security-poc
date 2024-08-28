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
package com.ericsson.oss.itpf.security.pki.common.test.response.generator;

import org.bouncycastle.asn1.cmp.PKIBody;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;

public class ResponseGeneratorFactory {

    public static ClientResponseGenerator getResponseGenerator(final ResponseType requestType) {
        ClientResponseGenerator messageGenerator = null;
        switch (requestType.getValue()) {

        case PKIBody.TYPE_INIT_REP:
            messageGenerator = new InitializationResponseGenerator();
            break;

        case PKIBody.TYPE_POLL_REP:
            messageGenerator = new PollResponseGenerator();
            break;

        case PKIBody.TYPE_CONFIRM:
            messageGenerator = new PKIConfResponseGenerator();
            break;

        case PKIBody.TYPE_KEY_UPDATE_REP:
            messageGenerator = new KeyUpdateResponseGenerator();
            break;

        case Constants.IP_WITH_WAIT:
            messageGenerator = new IPWithWaitResponseGenerator();
            break;
        }
        return messageGenerator;
    }

}
