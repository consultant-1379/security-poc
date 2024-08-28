/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.scriptengine.ejb.service;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum class for redirecting a command to a certain queue to be shared
 *
 */
public enum SynchronousCommandSet {

    AP("ap"),
    CONFIG("config"),
    CREDM("credm"),
    DHCP("dhcp"),
    LCMADM("lcmadm"),
    NHC("nhc"),
    PKIADM("pkiadm"),
    SECADM("secadm"),
    ADMIN("admin"),
    PUSHFILETRANSFER("pushfiletransfer");


    private final String command;

    private static final Map<String,Boolean> synchronousCommand = new HashMap<>();
    static {
        for (final SynchronousCommandSet s : SynchronousCommandSet.values()) {
            synchronousCommand.put(s.command, true);
        }
    }

    SynchronousCommandSet(final String command) {
        this.command = command;
    }

    public String getCommand() {
        return this.command;
    }

    public static boolean isSynchronousCommand(final String command) {
        if(command != null) {
            final Boolean found = synchronousCommand.get(command);
            if (found == null) {
                return false;
            } else {
                return found.booleanValue();
            }
        } else {
            return false;
        }
    }
}
