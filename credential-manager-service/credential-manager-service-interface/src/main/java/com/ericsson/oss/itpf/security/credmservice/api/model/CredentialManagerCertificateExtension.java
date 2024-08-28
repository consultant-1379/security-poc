/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;

public abstract class CredentialManagerCertificateExtension implements Serializable {
    /**
	 * 
	 */
    private static final long serialVersionUID = -5739589006460782189L;
    protected boolean critical;

    /**
     * @return the critical
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * @param critical
     *            the critical to set
     */
    public void setCritical(final boolean critical) {
        this.critical = critical;
    }

}
