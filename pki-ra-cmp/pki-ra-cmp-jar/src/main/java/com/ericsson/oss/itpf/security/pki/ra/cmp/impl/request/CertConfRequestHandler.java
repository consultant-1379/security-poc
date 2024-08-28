package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

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
 *----------------------------------------------------------------------------~*/

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolRequestType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.UseCommonValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common.PKIHeaderBodyValidator;

/**
 * This class handles CertConfirmation Request. When this request is received, it needs to be validated for Header/Body, Nonce validation, CRL and DigitalSignature.<br>
 * 
 * @author tcsdemi
 *
 */
@ProtocolRequestType(Constants.TYPE_CERT_CONF)
@UseCommonValidator({ PKIHeaderBodyValidator.class })
public class CertConfRequestHandler implements RequestHandler {

    @Inject
    private TransactionIdHandler transactionIDHandler;

    @Override
    public String handle(final RequestMessage pKIRequestMessage) throws TransactionIdHandlerException {

        final boolean tobeGenerated = false;
        String transactionId = null;
        transactionId = transactionIDHandler.handle(pKIRequestMessage, tobeGenerated);
        return transactionId;

    }

}
