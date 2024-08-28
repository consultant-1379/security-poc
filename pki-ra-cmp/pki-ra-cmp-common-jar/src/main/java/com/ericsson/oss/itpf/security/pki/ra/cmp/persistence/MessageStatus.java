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
package com.ericsson.oss.itpf.security.pki.ra.cmp.persistence;

/**
 * This ENUM class defines message status of a particular request
 * <p>
 * 1. NEW : All IR/KUR requests will have status as NEW untill IP/KUP is updated in DB.<br>
 * 2. WAIT_FOR_ACK: Response from pki-Manager if IP or KUP respective handler need to update DB status as this.<br>
 * 3.DONE: In case CertConf request is validated and pkiconf is sent, then pkiconf responseBuilder should update DB with this.<br>
 * 4.TO_REVOKE: In case user certificate is generated but from node either cert_conf is sent with rejected then this status is updated in DB.<br>
 * 5.FAILED: In case error message is sent from Manager then this status is updated<br>
 * 6.REVOKED_OLD_CERTIFICATE : In case Revocation is success then this status is updated for KUR.<br>
 * 7.REVOKED_NEW_CERTIFICATE : In case Revocation is success then this status is updated for KUR/IR.<br>
 * 8.REVOCATION_IN_PROGRESS_FOR_OLD_CERTIFICATE : Before going to Manager to call revocation API this will be updated with this status in case of KUR.<br>
 * 9.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE : Before going to Manager to call revocation API this will be updated with this status in case of KUR/IR if certconfirm is rejected.<br>
 * 10.TO_BE_REVOKED_NEW : if Revocation API Fails then this status is updated.<br>
 * 11.TO_BE_REVOKED_OLD : if Revocation API fails then this status is updated.<br>
 *
 * @author tcsramc
 *
 */
public enum MessageStatus {
    NEW(0, "NEW"), WAIT_FOR_ACK(1, "WAIT FOR ACK"), DONE(2, "DONE"), TO_BE_REVOKED(3, "TO BE REVOKED"), FAILED(4, "FAILED"), REVOKED_OLD_CERTIFICATE(5, "REVOKED OLD CERTIFICATE"), REVOKED_NEW_CERTIFICATE(
            6, "REVOKED NEW CERTIFICATE"), REVOCATION_IN_PROGRESS_FOR_OLD_CERTIFICATE(7, "REVOCATION IN PROGRESS FOR OLD CERTIFICATE"), REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE(8,
            "REVOCATION IN PROGRESS FOR NEW CERTIFICATE"), TO_BE_REVOKED_NEW(9, "TO BE REVOKED NEW"), TO_BE_REVOKED_OLD(10, "TO BE REVOKED OLD");

    private String status;
    private int value;

    private MessageStatus(final int value, final String transactionStatus) {
        this.status = transactionStatus;
        this.value = value;
    }

    @Override
    public String toString() {
        return status;

    }

    public int getValue() {
        return value;
    }

}
