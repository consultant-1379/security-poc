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

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.test.request.IAKInitialRequest;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;

public class IAKRequestGenerator implements ClientRequestGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(IAKRequestGenerator.class);

    @Override
    public PKIMessage generate(final Parameters parameters, final PKIMessage forInitialMessage) {

        PKIMessage pKIIAKMessage = null;
        try {
            final IAKInitialRequest iAKInitialRequest = new IAKInitialRequest(parameters);
            final PKIHeader pkiHeader = iAKInitialRequest.createPKIHeader();
            final PKIBody pkiBody = iAKInitialRequest.createPKIBody();
            final DERBitString signature = iAKInitialRequest.createSignatureString(pkiHeader, pkiBody);
            pKIIAKMessage = iAKInitialRequest.createPKIMessage(pkiHeader, pkiBody, signature);
        } catch (Exception exception) {
            LOGGER.debug("Exception Stacktrace: ", exception);
        }
        return pKIIAKMessage;
    }

}
