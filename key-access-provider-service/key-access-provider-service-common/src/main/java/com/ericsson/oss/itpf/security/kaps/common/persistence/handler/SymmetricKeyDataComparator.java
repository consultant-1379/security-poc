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
package com.ericsson.oss.itpf.security.kaps.common.persistence.handler;

import java.util.Comparator;

import com.ericsson.oss.itpf.security.kaps.common.persistence.entity.SymmetricKeyData;

/**
 * This class used to compare list of {@link SymmetricKeyData}
 */
public class SymmetricKeyDataComparator implements Comparator<SymmetricKeyData> {

    /**
     * compare all list of objects and arrange ascending order by id
     */
    @Override
    public int compare(final SymmetricKeyData symmetricKeyData1, final SymmetricKeyData symmetricKeyData2) {

        if (symmetricKeyData1.getId() > symmetricKeyData2.getId()) {
            return 1;
        } else if (symmetricKeyData1.getId() < symmetricKeyData2.getId()) {
            return -1;
        }
        return 0;
    }
}
