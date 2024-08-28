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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolRequestType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CMPRequestSigner;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.dispatcher.ProtocolServiceRequestDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceRequest;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.UseCommonValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.UseValidatorForVC;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common.PKIHeaderBodyValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class handles KeyUpdate Request. When this request is received, it needs to be validated for Header/Body, CRL and DigitalSignature.<br>
 * Nonce validation is not performed on this request since for the first request Sender/recepient nonce can be null and need not be verified. <br>
 * KeyUpdateRequestHandler will persist the RequestMessage into DB, and dispatch the request onto Modeled event bus to PKI-Manager for Certificate generation.
 *
 * 
 * @author tcsdemi
 *
 */
@ProtocolRequestType(Constants.TYPE_KEY_UPDATE_REQ)
@UseCommonValidator({ PKIHeaderBodyValidator.class })
//@UseValidatorForVC({ DigitalSignatureValidator.class, CRLValidator.class })
@UseValidatorForVC({ DigitalSignatureValidator.class })

public class KeyUpdateRequestHandler implements RequestHandler {

    @Inject
    private TransactionIdHandler transactionIDHandler;

    @Inject
    private ProtocolServiceRequestDispatcher cMPServiceRequestdispatcher;

    @Inject
    private PersistenceHandler persistenceHandler;

    @Inject
    CMPRequestSigner requestSigner;

    @Inject
    private CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Inject
    private CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Override
    public String handle(final RequestMessage pKIRequestMessage) throws TransactionIdHandlerException, InvalidInitialConfigurationException, DigitalSigningFailedException {

        String transactionID = null;

        final CertificateEnrollmentStatus certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(pKIRequestMessage.getSubjectName(), pKIRequestMessage.getIssuerName(),
                CertificateEnrollmentStatusType.START);
        if (certificateEnrollmentStatus != null) {
            certificateEnrollmentStatusDispatcher.dispatch(certificateEnrollmentStatus);
        }

        transactionID = handleTransactionID(pKIRequestMessage);

        save(pKIRequestMessage, transactionID);

        final byte[] signedXMLData = requestSigner.getCMPSignedXMLData(pKIRequestMessage, transactionID);

        dispatch(signedXMLData);

        return transactionID;
    }

    private String handleTransactionID(final RequestMessage pKIRequestMessage) throws TransactionIdHandlerException {
        String transactionId = null;
        transactionId = transactionIDHandler.handle(pKIRequestMessage, true);
        return transactionId;
    }

    private void save(final RequestMessage pKIRequestMessage, final String transactionID) {
        persistenceHandler.persist(pKIRequestMessage, transactionID);

    }

    private void dispatch(final byte[] signedXMLData) {
        final SignedCMPServiceRequest signedCMPServiceRequest = new SignedCMPServiceRequest();
        signedCMPServiceRequest.setCmpRequest(signedXMLData);
        cMPServiceRequestdispatcher.dispatch(signedCMPServiceRequest);
    }
}
