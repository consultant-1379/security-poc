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
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import org.bouncycastle.asn1.cmp.*;

/**
 * Class is used to build the Body of the Response message
 * 
 * @author tcsramc
 * 
 */
public class ResponseBody extends PKIBody {
    /**
     * This constructor is used to create PKIBody
     * 
     * @param type
     *            tag number
     * 
     * @param content
     *            the content that need to set in the PKIBody
     */
    public ResponseBody(final int type, final CertRepMessage content) {
        super(type, content);
    }

    /**
     * This constructor is used to create PKIBody
     * 
     * @param type
     *            tag number
     * 
     * @param content
     *            the content that need to set in the PKIBody
     */
    public ResponseBody(final int type, final PollRepContent content) {
        super(type, content);
    }

}
