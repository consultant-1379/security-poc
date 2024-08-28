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

import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;

import com.ericsson.oss.itpf.security.pki.common.model.PKIGeneralName;

/**
 * This class handles PKIHeader Creation.
 * 
 * @author tcsramc
 * 
 */
public class HeaderBuilder {
    private HeaderBuilder() {

    }

    /**
     * This method is used to create PKIHeader
     * 
     * @param header
     *            PKIHeader of PKIMessage
     * @param issuerName
     *            issuerName that need to set in PKIHeader
     * @return PKIHeaderBuilder Object
     */

    public static PKIHeaderBuilder create(final PKIHeader header, final PKIGeneralName issuerName) {

        final PKIHeaderBuilder builder = new PKIHeaderBuilder(header.getPvno().getValue().intValue(), issuerName, header.getRecipient());

        builder.setTransactionID(header.getTransactionID());
        builder.setSenderNonce(header.getSenderNonce());
        builder.setRecipNonce(header.getRecipNonce());
        builder.setProtectionAlg(header.getProtectionAlg());
        builder.setGeneralInfo(header.getGeneralInfo());
        builder.setMessageTime(header.getMessageTime());
        builder.setFreeText(header.getFreeText());
        builder.setSenderKID(header.getSenderKID());

        return builder;
    }

}
