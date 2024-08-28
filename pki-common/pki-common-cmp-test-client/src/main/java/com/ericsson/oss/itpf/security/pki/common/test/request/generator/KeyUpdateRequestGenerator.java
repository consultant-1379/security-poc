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

import com.ericsson.oss.itpf.security.pki.common.test.request.KeyUpdateRequest;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;

public class KeyUpdateRequestGenerator implements ClientRequestGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyUpdateRequestGenerator.class);

    @Override
    public PKIMessage generate(final Parameters parameters, final PKIMessage forInitialMessage) {

        PKIMessage pKIMessage = null;
        try {
            final KeyUpdateRequest keyUpdateRequest = new KeyUpdateRequest(parameters);
            final PKIHeader pkiHeader = keyUpdateRequest.createPKIHeader();
            final PKIBody pkiBody = keyUpdateRequest.createPKIBody();
            final DERBitString signature = keyUpdateRequest.createSignatureString(pkiHeader, pkiBody);
            pKIMessage = keyUpdateRequest.createPKIMessage(pkiHeader, pkiBody, signature);
        } catch (Exception exception) {
            LOGGER.debug("Exception Stacktrace: ", exception);
        }
        return pKIMessage;
    }

}
