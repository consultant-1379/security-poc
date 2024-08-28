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

import javax.xml.bind.annotation.XmlElement;

public class CredentialManagerAccessDescription implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -8003850279331944065L;
    @XmlElement(nillable = false, required = true)
    protected CredentialManagerAccessMethod accessMethod;
    @XmlElement(nillable = true, required = false)
    protected String accessLocation;

    /**
     * @return the accessMethod
     */
    public CredentialManagerAccessMethod getAccessMethod() {
        return accessMethod;
    }

    /**
     * @param accessMethod
     *            the accessMethod to set
     */
    public void setAccessMethod(final CredentialManagerAccessMethod accessMethod) {
        this.accessMethod = accessMethod;
    }

    /**
     * @return the accessLocation
     */
    public String getAccessLocation() {
        return accessLocation;
    }

    /**
     * @param accessLocation
     *            the accessLocation to set
     */
    public void setAccessLocation(final String accessLocation) {
        this.accessLocation = accessLocation;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " Access Description: [ AccessMethod: " + accessMethod + " AccessLocation: " + accessLocation + " ] ";
    }

}
