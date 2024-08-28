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
package com.ericsson.oss.itpf.security.pki.common.test.request.main;

import org.bouncycastle.asn1.cmp.PKIBody;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;

public enum RequestType {

    INITIALIZATION_REQUEST(PKIBody.TYPE_INIT_REQ, "INITIALIZATION REQUEST"), KEY_UPDATE_REQUEST(PKIBody.TYPE_KEY_UPDATE_REQ, "KEY UPDATE REQUEST"), CERT_CONFIRM(PKIBody.TYPE_CERT_CONFIRM,
            "CERTIFICATE CONFIRMATION"), POLL_REQUEST(PKIBody.TYPE_POLL_REQ, "POLL REQUEST"), IAK_REQUEST(Constants.IAK_REQUEST_ID, "IAK REQUEST");

    private int requestTypeNumber;
    private String requestMessageString;

    private RequestType(final int requestType, final String request) {
        this.requestTypeNumber = requestType;
        this.requestMessageString = request;

    }

    @Override
    public String toString() {
        return requestMessageString;
    }

    public int getValue() {
        return requestTypeNumber;
    }
}
