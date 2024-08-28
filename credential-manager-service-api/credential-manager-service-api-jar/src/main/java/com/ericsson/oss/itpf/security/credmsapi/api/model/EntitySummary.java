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
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import java.io.Serializable;

public class EntitySummary implements Serializable {

    private static final long serialVersionUID = -8236711112380248534L;

    private String name;
    private EntityStatus status;
    private Subject subject;

    
    /**
     * @param name
     * @param status
     * @param subject
     */
    public EntitySummary(final String name, final EntityStatus status, final Subject subject) {
        super();
        this.name = name;
        this.status = status;
        this.subject = subject;
    }

    /**
     * @return the name
     */
    public String getName() {
        return this.name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * @return the status
     */
    public EntityStatus getStatus() {
        return this.status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final EntityStatus status) {
        this.status = status;
    }

    /**
     * @return the subject
     */
    public Subject getSubject() {
        return this.subject;
    }

    /**
     * @param subject
     *            the subject to set
     */
    public void setSubject(final Subject subject) {
        this.subject = subject;
    }

    /**
     * @return the serialversionuid
     */
    public static long getSerialversionuid() {
        return serialVersionUID;
    }

}
