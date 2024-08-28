/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;
import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This class is used to build ResponseMessage(IP/KUP).
 * 
 * @author tcsramc
 *
 */
public abstract class ResponseMessageBuilder<T extends ResponseMessage> {

    private static final String issuer = "CN=dummy";

    protected abstract T createResponseMessage(final X509Certificate x509UserCertificate, final List<X509Certificate> x509trustedCertificates) throws ProtocolException, IOException;

    /**
     * 
     * @param pKIRequestMessage
     *            contains all the requiredFields for a requestMessage
     * @param transactionID
     *            transaction ID of the request message
     * @param x509UserCertificate
     *            user certificate fetched from the request message
     * @param x509ExtraCertificates
     *            certificates fetched from the extracerts od the request message
     * @param x509trustedCertificates
     *            trusted certificates fetched from the trust store
     * @param errorMessage
     * 
     * @return response message object
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     */
    public T generateResponseMessage(final RequestMessage pKIRequestMessage, final String transactionID, final X509Certificate x509UserCertificate, final List<X509Certificate> x509ExtraCertificates,
            final List<X509Certificate> x509trustedCertificates, final String errorMessage) throws IOException {
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = pKIRequestMessage.getSenderNonce();
        final String recipient = pKIRequestMessage.getSenderName();
        
        final T responseMessage = createResponseMessage(x509UserCertificate, x509trustedCertificates);
        responseMessage.setProtectionAlgorithm(pKIRequestMessage.getProtectAlgorithm().getEncoded());
        responseMessage.createPKIHeader(issuer, recipient, senderNonce, recipientNonce, transactionID);
        responseMessage.createPKIBody(responseMessage.getEncodableContent());
        responseMessage.createPKIMessage(x509ExtraCertificates);

        return responseMessage;
    }

}
