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

public class EntityInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * EntityInfo contains the entity identifier and OTP for ENIS operator
     */

    private String entityName;
    private String oneTimePassword;

    public EntityInfo() {
    }

    /**
     * @param entityName
     * @param oneTimePassword
     */
    public EntityInfo(final String entityName, final String oneTimePassword) {
        super();
        this.entityName = entityName;
        this.oneTimePassword = oneTimePassword;
    }

    /**
     * @return the entityName
     */
    public String getEntityName() {
        return entityName;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /**
     * @return the oneTimePassword
     */
    public String getOneTimePassword() {
        return oneTimePassword;
    }

    /**
     * @param oneTimePassword
     *            the oneTimePassword to set
     */
    public void setOneTimePassword(final String oneTimePassword) {
        this.oneTimePassword = oneTimePassword;
    }

    public boolean isValid() {

        if (this.entityName == null || this.entityName.isEmpty()) {
            return false;
        }

        if (this.oneTimePassword == null || this.oneTimePassword.isEmpty()) {
            return false;
        }

        return true;
    }
}
