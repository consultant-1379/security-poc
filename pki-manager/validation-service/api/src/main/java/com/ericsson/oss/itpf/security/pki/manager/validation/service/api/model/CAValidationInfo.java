/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * Model class which contains CAEntity and rekey/renew type.
 *
 * @author tcsmanp
 *
 */

public class CAValidationInfo {

    private CAEntity caEntity;

    private boolean newKey;

    /**
     * @return the caEntity
     */
    public CAEntity getCaEntity() {
        return caEntity;
    }

    /**
     * @param caEntity
     *            the caEntity to set
     */
    public void setCaEntity(final CAEntity caEntity) {
        this.caEntity = caEntity;
    }

    /**
     * @return the newKey
     */
    public boolean isNewKey() {
        return newKey;
    }

    /**
     * @param newKey
     *            the newKey to set
     */
    public void setNewKey(final boolean newKey) {
        this.newKey = newKey;
    }

}
