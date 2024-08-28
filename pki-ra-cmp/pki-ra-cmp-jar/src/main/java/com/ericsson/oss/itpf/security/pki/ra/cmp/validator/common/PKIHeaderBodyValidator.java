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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.BodyValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.HeaderValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.RequestValidator;

/**
 * This class has implementation to verify Header and Body validation. Header is
 * verified by the Version which should be "2" and also the Sender and recipient
 * Names should be in Directory format. Body should consist of only
 * IR/KUR/PollReq/CertConf, other requests are not supported by the
 * CMPv2Service.
 *
 * @author tcsdemi
 */
public class PKIHeaderBodyValidator implements RequestValidator {

    @Inject
    Logger logger;

    @Override
    public void validate(final RequestMessage pKIRequestMessage) throws HeaderValidationException, BodyValidationException {
        logger.info("Validating Header/Body for :{}", pKIRequestMessage.getRequestMessage());
        validateHeader(pKIRequestMessage);
        validateBody(pKIRequestMessage);
        logger.info("Validated Header/Body for : {}", pKIRequestMessage.getRequestMessage());
    }

    private void validateHeader(final RequestMessage pKIRequestMessage) throws HeaderValidationException {

        final String headerVersion = pKIRequestMessage.getPvNumber();
        String requestMessage = null;
        requestMessage = pKIRequestMessage.getRequestMessage();

        if (!isValidVersion(headerVersion)) {
            logger.error("Header validation failed for :{} ", requestMessage);
            logger.error("Invalid header version should be 2 but is : {}", headerVersion);
            throw new HeaderValidationException(ErrorMessages.HEADER_VERSION_ERROR);
        } else {
            logger.info(" Message header is validated for : {}", requestMessage);
        }

        if (!pKIRequestMessage.isSenderNameInDirectoryFormat()) {
            logger.error("Invalid Sender or recipient Name format for :{}", requestMessage);
            throw new HeaderValidationException(ErrorMessages.HEADER_SENDER_FORMAT_ERROR);
        }
        logger.debug("Sender and Issuer name is validated for : {}", pKIRequestMessage.getRequestMessage());
    }

    private void validateBody(final RequestMessage pKIRequestMessage) throws BodyValidationException {
        int requestType = 0;
        String requestMessage = null;
        requestMessage = pKIRequestMessage.getRequestMessage();
        requestType = pKIRequestMessage.getRequestType();

        if (!(requestType == Constants.TYPE_INIT_REQ || requestType == Constants.TYPE_KEY_UPDATE_REQ || requestType == Constants.TYPE_CERT_CONF || requestType == Constants.TYPE_POLL_REQ)) {
            logger.error("Invalid request Type while validating body for : {} ", requestMessage);
            throw new BodyValidationException(ErrorMessages.BODY_MESSAGE_TYPE_ERROR);
        }
        logger.info("Body is validated for : {}", requestMessage);
    }

    private boolean isValidVersion(final String cmpVersion) {

        boolean isValidVersion = true;
        if (Integer.parseInt(cmpVersion) != Constants.CMP_VERSION) {
            isValidVersion = false;
        }
        return isValidVersion;

    }

}
