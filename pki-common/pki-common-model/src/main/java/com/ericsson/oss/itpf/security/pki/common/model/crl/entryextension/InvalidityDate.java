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
package com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension;

import java.io.Serializable;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class InvalidityDate implements Serializable {

    private static final long serialVersionUID = 1766032672812760112L;

    // As per the RFC critical flag is always false for InvalidityDate. Hence making it final
    private static final boolean critical = false;

    private Date invalidityDate;

    /**
     * @return the critical
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * @return the invalidityDate
     */
    public Date getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * @param invalidityDate
     *            the invalidityDate to set
     */
    public void setInvalidityDate(final Date invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (critical ? 1231 : 1237);
        result = prime * result + ((invalidityDate == null) ? 0 : invalidityDate.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        final InvalidityDate other = (InvalidityDate) obj;
        if (critical != other.critical) {
            return false;
        }
        if (invalidityDate == null) {
            if (other.invalidityDate != null) {
                return false;
            }
        } else if (!invalidityDate.equals(other.invalidityDate)) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "InvalidityDate [critical=" + critical + ", invalidityDate=" + invalidityDate + "]";
    }

}
