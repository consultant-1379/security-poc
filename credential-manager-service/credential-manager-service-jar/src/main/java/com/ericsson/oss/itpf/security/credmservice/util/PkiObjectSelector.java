/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PkiObjectSelector {
    private static final Logger log = LoggerFactory.getLogger(PkiObjectSelector.class);

    public static Object getPkiObject(final Object... pkiObjects) {
        Object pkiObject = null;
        if (pkiObjects.length == 3) {
            if (pkiObjects[2] != null) {
                log.debug("pkiObjects size is 3, set pki object to 2");
                pkiObject = pkiObjects[2];
            } else {
                log.debug("pkiObjects size is 3 set pki object to 1");
                pkiObject = pkiObjects[1];
            }
        } else {
            log.error("not received the correct number of parameters");
        }
        return pkiObject;
    }

    public static boolean checkObjectAllocation(final Object... pkiObjects) {

        if (pkiObjects.length == 3) {
            if (pkiObjects[2] != null) {
                log.debug("pkiObjects[2] is valid");
                return true;
            } else {
                log.debug("pkiObjects[2] is NOT valid");
                return false;
            }
        } else {
            log.error("not received the correct number of parameters");
        }
        return false;
    }
}
