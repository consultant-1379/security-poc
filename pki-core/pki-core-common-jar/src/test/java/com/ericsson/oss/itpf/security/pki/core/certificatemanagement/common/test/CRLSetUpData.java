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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CRLData;

/**
 *  This class is used to set up initial test data for CRL
 */
public class CRLSetUpData {


    /**
     * Prepares CRLData to check for equals method.
     * @return CRLData
     */
    public CRLData getCRLDataForEqual() {
        final CRLData crlData = new CRLData();
        crlData.setCrl("crl".getBytes());
        crlData.setId(3);
        return crlData;
    }

    /**
     * Prepares CRLData to check for unequal method.
     * @return CRLData
     */
    public CRLData getCRLDataForNotEqual() {
        final CRLData crlData = new CRLData();
        crlData.setCrl("crlNew".getBytes());
        crlData.setId(6);
        return crlData;
    }

}
