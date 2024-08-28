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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderExceptionHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.KUPWithWaitResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

/**
 * This class implements ResponseBuilder. Builds KUP with wait response for KUR. Building response consists of: <br>
 * 1. Building PKIHeader/PKIbody/PKIMessage.<br>
 * 2. Signing the message.<br>
 * 3. Updating DB with the signed response and also status is necessary. <br>
 * 
 * @author tcsdemi
 *
 */
@ProtocolResponseType(Constants.TYPE_KU_RESPONSE_WAIT)
public class KeyUpdateWaitResponseBuilder extends ResponseMessageSigningHelper implements ResponseBuilder {

    @Inject
    ConfigurationParamsListener cMPConfigurationListener;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Override
    public byte[] build(final RequestMessage keyUpdateRequest, final String transactionID) throws ResponseBuilderException {

        byte[] signedKUPResponseMessage = null;

        logger.info("Signing Wait response for Key update Request.");
        try {
            final String senderName = keyUpdateRequest.getSenderName();
            final KUPWithWaitResponseMessage keyUpdateWaitResponse = new KUPWithWaitResponseMessage();
            createKUPWithWaitResponseMessage(keyUpdateRequest, transactionID, keyUpdateWaitResponse);
            signedKUPResponseMessage = responseMessageSigningHelper.signMessage(keyUpdateRequest.getIssuerName(), keyUpdateWaitResponse);
            final CMPMessageEntity protocolMessageEntity = createMessageEntity(senderName, transactionID, signedKUPResponseMessage);
            persistenceHandler.updateEntity(protocolMessageEntity);

        } catch (IOException ioException) {
            ResponseBuilderExceptionHelper.throwCustomException(ioException);

        } catch (InvalidInitialConfigurationException initialConfigurationException) {
            ResponseBuilderExceptionHelper.throwCustomException(initialConfigurationException);

        } catch (ProtectionEncodingException protectionEncodingException) {
            ResponseBuilderExceptionHelper.throwCustomException(protectionEncodingException);

        } catch (ResponseSignerException responseSignerException) {
            ResponseBuilderExceptionHelper.throwCustomException(responseSignerException);
        }
        logger.info("Signed waiting response for Key update request.");
        return signedKUPResponseMessage;

    }

    private CMPMessageEntity createMessageEntity(final String senderName, final String transactionID, final byte[] signedIPResponseMessage) {
        final CMPMessageEntity protocolMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        final String dEREncodedSenderNonce = new KUPWithWaitResponseMessage(signedIPResponseMessage).getSenderNonce();
        protocolMessageEntity.setSenderNonce(dEREncodedSenderNonce);
        protocolMessageEntity.setResponseMessage(signedIPResponseMessage);
        return protocolMessageEntity;

    }

    private void createKUPWithWaitResponseMessage(final RequestMessage keyUpdateRequest, final String transactionID, final KUPWithWaitResponseMessage keyUpdateWaitResponse) throws IOException {
        final String issuer = responseMessageSigningHelper.getSenderFromSignerCert(keyUpdateRequest.getIssuerName());
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = keyUpdateRequest.getSenderNonce();
        final String recipient = keyUpdateRequest.getSenderName();
        final int certRequestId = keyUpdateRequest.getRequestId();
        final byte[] encodedProtectionAlgorithm = keyUpdateRequest.getProtectAlgorithm().getEncoded();
        final List<X509Certificate> cMPExtraCertificates = responseMessageSigningHelper.addSignerCertandCertChainToCMPExtraCertificates(keyUpdateRequest.getIssuerName());

        keyUpdateWaitResponse.setProtectionAlgorithm(encodedProtectionAlgorithm);
        keyUpdateWaitResponse.createPKIHeader(issuer, recipient, senderNonce, recipientNonce, transactionID);
        keyUpdateWaitResponse.createWaitCertRepMessage(certRequestId);
        keyUpdateWaitResponse.createPKIBody(keyUpdateWaitResponse.getWaitCertRepMessage());
        keyUpdateWaitResponse.createPKIMessage(cMPExtraCertificates);
        keyUpdateWaitResponse.setIssuerName(keyUpdateRequest.getIssuerName());
    }

}
