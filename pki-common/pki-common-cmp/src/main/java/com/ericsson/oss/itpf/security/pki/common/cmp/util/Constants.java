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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;

/**
 * Contains constants
 * 
 * @author tcsramc
 * 
 */
public class Constants {

    private Constants() {

    }

    public static final int TYPE_INIT_REQ = PKIBody.TYPE_INIT_REQ;
    public static final int TYPE_INIT_RESPONSE = PKIBody.TYPE_INIT_REP;
    public static final int TYPE_POLL_REQ = PKIBody.TYPE_POLL_REQ;
    public static final int TYPE_POLL_RESPONSE = PKIBody.TYPE_POLL_REP;
    public static final int TYPE_CERT_CONF = PKIBody.TYPE_CERT_CONFIRM;
    public static final int TYPE_PKI_CONF = PKIBody.TYPE_CONFIRM;
    public static final int TYPE_KEY_UPDATE_REQ = PKIBody.TYPE_KEY_UPDATE_REQ;
    public static final int TYPE_KEY_UPDATE_RESPONSE = PKIBody.TYPE_KEY_UPDATE_REP;
    public static final int TYPE_ERROR_RESPONSE = PKIBody.TYPE_ERROR;
    public static final int CMP_VERSION = PKIHeader.CMP_2000;
    public static final int TYPE_INIT_RESPONSE_WAIT = 100;
    public static final int TYPE_KU_RESPONSE_WAIT = 101;
    public static final int INVALID_REQUEST = 400;
    public static final int UNKNOWN_ERROR_RESPONSE = 3;
    public static final int CMP_ERRORED_RESPONSE = 2;
    public static final int KEY_UPDATE_RESPONSE = 1;
    public static final int INITIALIZATION_RESPONSE = 0;

}
