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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class CrlEntryExtensions implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -5737915988643590438L;

    private InvalidityDate invalidityDate;

    private ReasonCode reasonCode;

    /**
     * @return the invalidityDate
     */
    public InvalidityDate getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * @param invalidityDate
     *            the invalidityDate to set
     */
    public void setInvalidityDate(final InvalidityDate invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    /**
     * @return the reasonCode
     */
    public ReasonCode getReasonCode() {
        return reasonCode;
    }

    /**
     * @param reasonCode
     *            the reasonCode to set
     */
    public void setReasonCode(final ReasonCode reasonCode) {
        this.reasonCode = reasonCode;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((invalidityDate == null) ? 0 : invalidityDate.hashCode());
        result = prime * result + ((reasonCode == null) ? 0 : reasonCode.hashCode());
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
        
        final CrlEntryExtensions other = (CrlEntryExtensions) obj;
        if (invalidityDate == null) {
            if (other.invalidityDate != null) {
                return false;
            }
        } else if (!invalidityDate.equals(other.invalidityDate)) {
            return false;
        }
        
        if (reasonCode == null) {
            if (other.reasonCode != null) {
                return false;
            }
        } else if (!reasonCode.equals(other.reasonCode)) {
            return false;
        }
        
        return true;
    }

    @Override
    public String toString() {
        return "CrlEntryExtensions [invalidityDate=" + invalidityDate + ", reasonCode=" + reasonCode + "]";
    }

}
