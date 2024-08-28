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

import org.bouncycastle.asn1.cmp.*;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;

/**
 * The purpose of this class to include all utility methods which are required to extract certConfstatus from RequestMessage.<br>
 * Method:<code> get(final RequestMessage pKIMessage)</code> will return MessageStatus which is an ENUM to store status of the transaction.
 * <p>
 * Note: Please refer to MessageStatus class for status values.
 * 
 * @author tcsdemi
 *
 */
public class CertConfStatusUtil {

    private CertConfStatusUtil() {

    }

    private static final int ACCEPTED = 0;
    private static final int REJECTED = 2;

    /**
     * This method returns the default status values in case PKIStatusInfo or certStatus fields are missing as:<br>
     * 1. In case certStatus dataStructure itself is missing then according to RFC4210 it conveys that certificate is REJECTED. <br>
     * 2. In case certStatus->PKIStatusInfo is missing then according to RFC4210 it denotes that certificate is ACCEPTED.
     * 
     * @param pKIMessage
     *            This is certConf request Message, body of which contains CertConfirmContent.
     * @return String <br>
     *         Returns status either DONE or TO_REVOKE messageStatus. Please refer to MessageStatus for all supported status types.
     */
    public static MessageStatus get(final RequestMessage pKIMessage) {
        MessageStatus certConfStatus = MessageStatus.TO_BE_REVOKED;
        final CertConfirmContent certConfirmContent = (CertConfirmContent) pKIMessage.getPKIBody().getContent();
        final CertStatus[] certStatus = certConfirmContent.toCertStatusArray();
        int status = 0;

        status = getDefaultCertStatus(certStatus);

        switch (status) {
        case ACCEPTED:
            certConfStatus = MessageStatus.DONE;
            break;

        case REJECTED:
        default:
            break;

        }
        return certConfStatus;
    }

    private static int getDefaultCertStatus(final CertStatus[] certStatus) {
        PKIStatusInfo pKIStatusInfo;
        int status;
        pKIStatusInfo = certStatus[0].getStatusInfo();
        if (certStatus[0] != null) {
            if (pKIStatusInfo != null) {
                status = pKIStatusInfo.getStatus().intValue();
            } else {
                status = ACCEPTED;
            }
        } else {
            status = REJECTED;
        }
        return status;
    }

}
