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
import java.util.ArrayList;
import java.util.List;

public class CredentialManagerCALists implements Serializable {

    private static final long serialVersionUID = 1L;

    private final List<CredentialManagerTrustCA> internalCAList;

    private final List<CredentialManagerTrustCA> externalCAList;

    /**
     * 
     */
    public CredentialManagerCALists() {

        this.internalCAList = new ArrayList<CredentialManagerTrustCA>();
        this.externalCAList = new ArrayList<CredentialManagerTrustCA>();
    }

    /**
     * @return the internalCAList
     */
    public List<CredentialManagerTrustCA> getInternalCAList() {
        return internalCAList;
    }

    /**
     * @param internalCAList
     *            the internalCAList to set
     */
    //    public void setInternalCAList(final List<CredentialManagerTrustCA> internalCAList) {
    //        this.internalCAList = internalCAList;
    //    }

    /**
     * @return the externalCAList
     */
    public List<CredentialManagerTrustCA> getExternalCAList() {
        return externalCAList;
    }

    /**
     * @param externalCAList
     *            the externalCAList to set
     */
    //    public void setExternalCAList(final List<CredentialManagerTrustCA> externalCAList) {
    //        this.externalCAList = externalCAList;
    //    }

}
