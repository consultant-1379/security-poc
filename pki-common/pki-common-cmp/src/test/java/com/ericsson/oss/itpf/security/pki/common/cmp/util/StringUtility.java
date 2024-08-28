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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import org.bouncycastle.asn1.x500.X500Name;

public class StringUtility {

    public static boolean isEquals(X500Name certSubjectName, String senderName) {
        boolean isEqual = false;
        if (certSubjectName.equals(new X500Name(senderName))) {
            isEqual = true;
        }
        return isEqual;
    }

}
