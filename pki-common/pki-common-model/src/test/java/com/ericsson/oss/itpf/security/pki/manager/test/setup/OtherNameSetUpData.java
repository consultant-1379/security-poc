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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;

/**
 * This class acts as builder for {@link OtherNameSetUpData}
 */
public class OtherNameSetUpData {
    /**
     * Method that returns valid OtherName
     * 
     * @return OtherName
     */
    public OtherName getOtherName(final String typeId, final String value) {
        final OtherName otherName = new OtherName();
        otherName.setTypeId(typeId);
        otherName.setValue(value);
        return otherName;
    }
}
