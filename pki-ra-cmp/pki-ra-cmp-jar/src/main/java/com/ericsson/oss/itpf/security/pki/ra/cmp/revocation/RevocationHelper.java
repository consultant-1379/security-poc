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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation;

import java.io.IOException;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CertConfStatusUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

public class RevocationHelper {

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    Logger logger;

    /**
     * This method is used to update the status,once the revocation request is passed to API over the event bus.
     * 
     * @param RequestMessage
     *            from which current status is fetched.
     * @throws MessageParsingException
     *             is thrown when Message parsing error occurs.
     * @throws CertificateParseException
     *             is thrown when Certificate parsing error occurs.
     * @throws InvalidCertificateVersionException
     *             is thrown if certificate version is invalid
     * @throws IOException
     *             is thrown if any i/o error occurs.
     */
    public void updateRevocationStatus(final RequestMessage RequestMessage) throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException, IOException {
        final MessageStatus certConfStatus = CertConfStatusUtil.get(RequestMessage);
        final CMPMessageEntity protocolMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(RequestMessage.getBase64TransactionID(), RequestMessage.getSenderName());
        switch (certConfStatus) {
        case DONE:
            persistenceHandler.updateEntityStatus(protocolMessageEntity, MessageStatus.REVOCATION_IN_PROGRESS_FOR_OLD_CERTIFICATE);
            break;

        case TO_BE_REVOKED:
            persistenceHandler.updateEntityStatus(protocolMessageEntity, MessageStatus.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE);
            break;

        default:
            logger.info("Certificate need not be revoked, since status could be DONE for IR");
            break;
        }
        persistenceHandler.updateEntity(protocolMessageEntity);
    }

}
