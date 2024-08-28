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

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderExceptionHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.IPWithWaitResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

/**
 * This class implements ResponseBuilder. Builds IP with wait response for IR. Building response consists of: <br>
 * 1. Building PKIHeader/PKIbody/PKIMessage.<br>
 * 2. Signing the message.<br>
 * 3. Updating DB with the signed response and also status is necessary. <br>
 * 
 * @author tcsdemi
 *
 */
@ProtocolResponseType(Constants.TYPE_INIT_RESPONSE_WAIT)
public class IPWithWaitResponseBuilder implements ResponseBuilder {

    @Inject
    Logger logger;

    @Inject
    InitialConfiguration configurationData;

    @Inject
    ConfigurationParamsListener cMPConfigurationListener;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Override
    public byte[] build(final RequestMessage pKIIRRequestmessage, final String transactionID) throws ResponseBuilderException {
        byte[] signedIPResponseMessage = null;
        try {

            final IPWithWaitResponseMessage ipWithWaitResponseMessage = new IPWithWaitResponseMessage();
            final String senderName = pKIIRRequestmessage.getSenderName();
            logger.info("Creating IP with wait response message");
            createIPWithWaitResponseMessage(pKIIRRequestmessage, transactionID, ipWithWaitResponseMessage);
            signedIPResponseMessage = responseMessageSigningHelper.signMessage(pKIIRRequestmessage.getIssuerName(), ipWithWaitResponseMessage);
            final CMPMessageEntity protocolMessageEntity = createMessageEntity(senderName, transactionID, signedIPResponseMessage);
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

        logger.info(" Created IP with wait PKI response Message and sending the same to entity.");
        return signedIPResponseMessage;

    }

    private CMPMessageEntity createMessageEntity(final String senderName, final String transactionID, final byte[] signedIPResponseMessage) {

        final CMPMessageEntity protocolMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        final String dEREncodedSenderNonce = new IPWithWaitResponseMessage(signedIPResponseMessage).getSenderNonce();
        protocolMessageEntity.setResponseMessage(signedIPResponseMessage);
        protocolMessageEntity.setSenderNonce(dEREncodedSenderNonce);
        return protocolMessageEntity;
    }

    private void createIPWithWaitResponseMessage(final RequestMessage pKIIRRequestmessage, final String transactionID, final IPWithWaitResponseMessage ipWithWaitResponseMessage)
            throws InvalidInitialConfigurationException, IOException {
        final String issuer = responseMessageSigningHelper.getSenderFromSignerCert(pKIIRRequestmessage.getIssuerName());
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = pKIIRRequestmessage.getSenderNonce();
        final String recipient = pKIIRRequestmessage.getSenderName();
        final int certRequestId = pKIIRRequestmessage.getRequestId();
        final List<X509Certificate> cmpExtraCertificates = responseMessageSigningHelper.addSignerCertandCertChainToCMPExtraCertificates(pKIIRRequestmessage.getIssuerName());

        final byte[] encodedProtectionAlgorithm = pKIIRRequestmessage.getProtectAlgorithm().getEncoded();

        ipWithWaitResponseMessage.setProtectionAlgorithm(encodedProtectionAlgorithm);
        ipWithWaitResponseMessage.createPKIHeader(issuer, recipient, senderNonce, recipientNonce, transactionID);
        ipWithWaitResponseMessage.createWaitCertRepMessage(certRequestId);
        ipWithWaitResponseMessage.createPKIBody(ipWithWaitResponseMessage.getWaitCertRepMessage());
        ipWithWaitResponseMessage.createPKIMessage(cmpExtraCertificates);
        ipWithWaitResponseMessage.setIssuerName(pKIIRRequestmessage.getIssuerName());
    }

}
