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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.util;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidMessageException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

/**
 * This class is used to return appropriate trusts based on the requestType. <br>
 * For eg: In case of IR external trusts needs to be used,in case of KUR internal trusts needs to be used, for DigitalSignature.
 * 
 * @author tcsdemi
 *
 */
public class TrustStoreUtil {

    @Inject
    InitialConfiguration configurationData;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    Logger logger;

    /**
     * This method will give appropriate Trusts based on Request Type:<br>
     * 1. In case of IR, Vendor Certificates are returned<br>
     * 2. In case of KUR, CA certificates are returned<br>
     * 3. In case of PollRequest/CertConf consequent to IR, VendorCertificates are returned<br>
     * 4. In case of PollRequest/CertConf consequent to KUR CA certificates are returned
     * 
     * @param pKIRequestMessage
     * @return
     * @throws InvalidInitialConfigurationException
     *             thrown if vendor and CA certificates are not initialized properly
     * @throws InvalidMessageException
     *             In case requestType is other than IR/KUR/CertConf/Poll
     * @throws IOException
     *             In case RequestMessage can not be initialized properly
     * @throws MessageParsingException
     *             In case RequestMessage is corrupted or invalid data is present
     * @throws CertificateParsingException
     *             Certificate within RequestMessage is invalid
     * @throws InvalidCertificateVersionException
     *             Certificate version within the RequestMessage is not X509v3
     */
    public Set<X509Certificate> getTrustedCertsBasedOnRequestType(final RequestMessage pKIRequestMessage) throws InvalidInitialConfigurationException, InvalidMessageException, IOException,
            MessageParsingException, CertificateParseException, InvalidCertificateVersionException {

        Set<X509Certificate> trustedCertificates = null;

        final int requestType = pKIRequestMessage.getRequestType();
        switch (requestType) {

        case Constants.TYPE_INIT_REQ:
            trustedCertificates = configurationData.getVendorCertificateSet();
            break;

        case Constants.TYPE_KEY_UPDATE_REQ:
            trustedCertificates = configurationData.getCaCertificateSet();
            break;

        case Constants.TYPE_POLL_REQ:
        case Constants.TYPE_CERT_CONF:
            trustedCertificates = getTrustForInitialRequest(pKIRequestMessage);
            break;

        default:
            logger.error("While fetching trust store, only IR/KUR/PollingRequest and CertConf requestType is supported");
            throw new InvalidMessageException(ErrorMessages.UNKNOWN_MESSAGE_TYPE);
        }

        return trustedCertificates;
    }

    private Set<X509Certificate> getTrustForInitialRequest(final RequestMessage pKIRequestMessage) throws IOException {
        String transactionId = null;
        RequestMessage initialMessage = null;
        Set<X509Certificate> trustedCertificates = null;

        final String senderName = pKIRequestMessage.getSenderName();
        transactionId = pKIRequestMessage.getBase64TransactionID();
        final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName);
        if (cMPMessageEntity == null) {
            logger.error("Error while fetching trust store, protocol Message entity is null for the transactionID :{} while processing : {}  ", transactionId,
                    pKIRequestMessage.getRequestMessage());
            throw new InvalidMessageException(ErrorMessages.IMPROPER_INITIAL_MESSAGE);
        }
        initialMessage = new RequestMessage(cMPMessageEntity.getInitialMessage());
        trustedCertificates = configurationData.getTrustedCerts(initialMessage.getRequestType());
        return trustedCertificates;
    }
}
