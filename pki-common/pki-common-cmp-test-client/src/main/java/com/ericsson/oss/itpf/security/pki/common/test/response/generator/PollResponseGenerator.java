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

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.response.PollResponse;

public class PollResponseGenerator implements ClientResponseGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(PollResponseGenerator.class);

    @Override
    public PKIMessage generate(final PKIMessage message, final Parameters parameters) {
        PKIMessage pKIMessage = null;
        try {
            final PollResponse pollResponse = new PollResponse(parameters);
            final PKIHeader pKIHeader = pollResponse.createPKIHeader(message);
            final PKIBody pKIbody = pollResponse.createPKIBody(message);
            final DERBitString signature = pollResponse.createSignatureString(pKIHeader, pKIbody);
            pKIMessage = pollResponse.createPKIMessage(pKIHeader, pKIbody, signature);
        } catch (Exception exception) {
            LOGGER.debug("Exception Stacktrace: ", exception);
        }
        return pKIMessage;
    }

}
