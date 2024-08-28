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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;

/**
 * This class acts as builder for {@link EdiPartyNameSetUpData}
 */
public class EdiPartyNameSetUpData {
    /**
     * 
     * @param nameAssigner
     * @param partyName
     * @return
     */
    public EdiPartyName getEdiPartyName(final String nameAssigner, final String partyName) {
        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setNameAssigner(nameAssigner);
        ediPartyName.setPartyName(partyName);
        return ediPartyName;
    }
}
