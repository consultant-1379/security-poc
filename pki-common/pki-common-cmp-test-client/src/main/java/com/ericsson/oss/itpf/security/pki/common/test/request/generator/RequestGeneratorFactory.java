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
package com.ericsson.oss.itpf.security.pki.common.test.request.generator;

import java.security.Security;

import org.bouncycastle.asn1.cmp.PKIBody;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.RequestType;

public class RequestGeneratorFactory {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static ClientRequestGenerator getRequestGenerator(final RequestType requestType) {
        ClientRequestGenerator messageGenerator = null;
        switch (requestType.getValue()) {

        case PKIBody.TYPE_INIT_REQ:
            messageGenerator = new InitializationRequestGenerator();
            break;

        case PKIBody.TYPE_POLL_REQ:
            messageGenerator = new PollRequestGenerator();
            break;

        case PKIBody.TYPE_CERT_CONFIRM:
            messageGenerator = new CertConfRequestGenerator();
            break;

        case PKIBody.TYPE_KEY_UPDATE_REQ:
            messageGenerator = new KeyUpdateRequestGenerator();
            break;

        case Constants.IAK_REQUEST_ID:
            messageGenerator = new IAKRequestGenerator();
            break;
        }
        return messageGenerator;
    }
}
