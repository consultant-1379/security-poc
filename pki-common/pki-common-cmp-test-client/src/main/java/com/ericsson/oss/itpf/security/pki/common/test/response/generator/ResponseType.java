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
package com.ericsson.oss.itpf.security.pki.common.test.response.generator;

import org.bouncycastle.asn1.cmp.PKIBody;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;

public enum ResponseType {

    INITIALIZATION_RESPONSE(PKIBody.TYPE_INIT_REP, "INITIALIZATION RESPONSE"), KEY_UPDATE_RESPONSE(PKIBody.TYPE_KEY_UPDATE_REP, "KEY UPDATE RESPONSE"), PKI_CONF(PKIBody.TYPE_CONFIRM,
            "PKI CONFIRMATION"), POLL_RESPONSE(PKIBody.TYPE_POLL_REP, "POLL RESPONSE"), IP_WITH_WAIT_RESPONSE(Constants.IP_WITH_WAIT, "IP WITH WAIT RESPONSE");

    private int responseTypeNumber;
    private String responseMessageString;

    private ResponseType(final int responseType, final String response) {
        this.responseTypeNumber = responseType;
        this.responseMessageString = response;

    }

    @Override
    public String toString() {
        return responseMessageString;
    }

    public int getValue() {
        return responseTypeNumber;
    }
}
