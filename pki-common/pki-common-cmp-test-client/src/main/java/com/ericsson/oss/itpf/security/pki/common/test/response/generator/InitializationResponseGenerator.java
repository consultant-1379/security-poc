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
import com.ericsson.oss.itpf.security.pki.common.test.response.InitializationResponse;

public class InitializationResponseGenerator implements ClientResponseGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(InitializationResponseGenerator.class);

    @Override
    public PKIMessage generate(final PKIMessage message, final Parameters parameters) {
        PKIMessage pKIMessage = null;
        try {
            InitializationResponse ipResponse;
            ipResponse = new InitializationResponse(parameters);
            final PKIHeader pKIHeader = ipResponse.createPKIHeader(message);
            final PKIBody pKIbody = ipResponse.createPKIBody(message);
            final DERBitString signature = ipResponse.createSignatureString(pKIHeader, pKIbody);
            pKIMessage = ipResponse.createPKIMessage(pKIHeader, pKIbody, signature);
        } catch (Exception exception) {
            LOGGER.debug("Exception Stacktrace: ", exception);
        }

        return pKIMessage;
    }
}
