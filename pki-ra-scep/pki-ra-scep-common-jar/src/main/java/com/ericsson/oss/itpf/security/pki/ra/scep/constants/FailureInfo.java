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
package com.ericsson.oss.itpf.security.pki.ra.scep.constants;

/**
 * This class specifies the failure scenarios which are supported by SCEP protocol requests. This failure info values are defined according to SCEP Draft. getScepFailInfo method returns the failInfo
 * integer value which is defined by SCEP Draft
 *
 * @author xtelsow
 */
public enum FailureInfo {
    BADALG(0),

    BADMESSAGECHECK(1),

    BADREQUEST(2),

    BADTIME(3);

    int scepFailInfo;

    FailureInfo(final int value) {
        this.scepFailInfo = value;
    }

    /**
     * @return the scepFailInfo
     */
    public int getScepFailInfo() {
        return scepFailInfo;
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
