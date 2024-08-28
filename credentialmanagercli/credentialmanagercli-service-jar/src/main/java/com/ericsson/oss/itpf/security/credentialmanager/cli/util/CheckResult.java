/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.util;

import java.util.HashMap;
import java.util.Map;

public class CheckResult {

    private final Map<String, Boolean> singleResult = new HashMap<String, Boolean>();

    /**
     * @param args
     */

    public CheckResult() {
        this.singleResult.put("certificateUpdate", false);
        this.singleResult.put("trustUpdate", false);
        this.singleResult.put("crlUpdate", false);
    }

    public void setResult(final String cause, final Boolean result) {

        if (this.singleResult.containsKey(cause)) {
            this.singleResult.put(cause, result);
        }
    }

    public Boolean isAllFalse() {
        return !(this.singleResult.get("certificateUpdate") || this.singleResult.get("trustUpdate") || this.singleResult.get("crlUpdate"));
    }

    public Boolean getResult(final String cause) {

        return this.singleResult.get(cause);
    }

}
