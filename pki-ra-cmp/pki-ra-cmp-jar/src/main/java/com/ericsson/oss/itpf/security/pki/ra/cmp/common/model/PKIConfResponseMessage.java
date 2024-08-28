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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.model;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;

/**
 * This class defines PKIConf response message which extends ResponseMessage
 * <p>
 * Note: Please refer to ResponseMessage class
 * 
 * @author tcsdemi
 *
 */
public class PKIConfResponseMessage extends ResponseMessage {
    private static final long serialVersionUID = -7278949995097252294L;

    @Override
    public void createPKIBody(final ASN1Encodable content) {
        responsePKIBody = new PKIBody(Constants.TYPE_PKI_CONF, new PKIConfirmContent());
    }
}
