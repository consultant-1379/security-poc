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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import java.util.Comparator;

import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;

public class ComparatorUtil implements Comparator<CertificateData> {

    @Override
    public int compare(final CertificateData certificateData1, final CertificateData certificateData2) {

        if (certificateData1.getId() > certificateData2.getId()) {
            return 1;
        } else if (certificateData1.getId() < certificateData2.getId()) {
            return -1;
        }
        return 0;
    }
}
