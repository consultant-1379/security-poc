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
package com.ericsson.oss.itpf.security.pki.common.model.crl.revocation;

/**
 * This class is used to represent Revocation Request Status 
 * <ul>
 * <li>NEW: Status is set to NEW once the revocation request is placed for CA/End Entity.</li>
 * <li>REVOKED: Status is set to REVOKED when revocation request is successful.</li>
 * <li>FAILED: Status is set to FAILED when revocation request is failed.</li>
 * </ul>
 * 
 */
public enum RevocationRequestStatus {

    NEW(0), REVOKED(1), FAILED(2);
    
    private int revocationStatus;
    
    RevocationRequestStatus(final int value) {
        this.revocationStatus = value;
    }
    
    public static RevocationRequestStatus fromValue(final String v) {
        return valueOf(v);
    }
    
    /**
     *  Get Enum value from id.
     * 
     * @return revocationReason
     */
    public int getRevocationStatus() {
        return revocationStatus;
    }
    
    /**
    * Get Enum value from String.
    *
    * @param value
    * @return RevocationReason
    */
   public static RevocationRequestStatus getNameByValue(final int value) {
       for (final RevocationRequestStatus reason : RevocationRequestStatus.values()) {
           if (reason.revocationStatus == value) {
               return reason;
           }
       }
       return null;
   }
   
   /**
    * {@inheritDoc}
    *
    * @see java.lang.Enum#toString()
    */
   @Override
   public String toString() {
       return name();
   }
}
