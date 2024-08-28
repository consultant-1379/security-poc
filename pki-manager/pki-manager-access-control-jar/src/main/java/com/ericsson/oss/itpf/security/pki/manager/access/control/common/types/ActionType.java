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
package com.ericsson.oss.itpf.security.pki.manager.access.control.common.types;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

public enum ActionType {
    CREATE("create"), READ("read"), UPDATE("update"), DELETE("delete"), IMPORT("import"), EXPORT("export");
    private final String name;

    private ActionType(final String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static ActionType getActionType(final String name) {
        for (final ActionType actionType : ActionType.values()) {
            if (actionType.getName().equals(name)) {
                return actionType;
            }
        }
        throw new CertificateServiceException("");

    }

    @Override
    public String toString() {
        return super.toString();
    }
}
