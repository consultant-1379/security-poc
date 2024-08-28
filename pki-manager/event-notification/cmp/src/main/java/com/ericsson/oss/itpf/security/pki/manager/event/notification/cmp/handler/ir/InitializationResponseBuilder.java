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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ResponseMessageBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception.ExceptionHelper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception.ResponseEventBuilderException;

/**
 * This class builds InitialResponse
 * 
 * @author tcsramc
 * 
 */
public class InitializationResponseBuilder extends ResponseMessageBuilder<ResponseMessage> {

    protected List<X509Certificate> x509trustedCertificates;
    protected X509Certificate x509UserCertificate;
    private int certRequestId = 0;

    @Override
    protected ResponseMessage createResponseMessage(final X509Certificate x509UserCertificate, final List<X509Certificate> x509trustedCertificates) {
        final IPResponseMessage iPResponseMessage = new IPResponseMessage();
        iPResponseMessage.createCertRepMessage(certRequestId, x509UserCertificate, x509trustedCertificates);
        return iPResponseMessage;
    }

    /**
     * This method generates InitialResponse Message with Proper PKIHeader,PKIBody,and ExtraCerts.
     * 
     * @param pKIRequestMessage
     *            KeyUpdateRequestMessage
     * @param transactionID
     *            uniqueID generated in the transaction startup.
     * @param x509UserCertificate
     *            User certificate.
     * @param x509ExtraCertificates
     *            CertificateChain
     * @param x509trustedCertificates
     *            list of trustCertificates.
     * @return IPResponseMessage
     * @throws ResponseEventBuilderException
     *             is thrown if any I/O Exception occurs.
     */
    public IPResponseMessage build(final RequestMessage pKIRequestMessage, final String transactionID, final X509Certificate x509UserCertificate, final List<X509Certificate> x509ExtraCertificates,
            final List<X509Certificate> x509trustedCertificates) throws ResponseEventBuilderException {
        IPResponseMessage ipResponseMessage = null;
        try {
            this.x509trustedCertificates = x509trustedCertificates;
            this.x509UserCertificate = x509UserCertificate;
            this.certRequestId = pKIRequestMessage.getRequestId();
            ipResponseMessage = (IPResponseMessage) generateResponseMessage(pKIRequestMessage, transactionID, x509UserCertificate, x509ExtraCertificates, x509trustedCertificates, null);
        } catch (IOException iOException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.IO_EXCEPTION, iOException);

        }

        return ipResponseMessage;
    }
}
