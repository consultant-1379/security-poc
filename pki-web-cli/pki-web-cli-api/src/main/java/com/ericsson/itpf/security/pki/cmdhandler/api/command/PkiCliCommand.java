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

package com.ericsson.itpf.security.pki.cmdhandler.api.command;

import java.util.HashMap;
import java.util.Map;

/**
 * Subclass of PkiCommand which expects a com.ericsson.itpf.security.pki.cmdhandler.api.command line type of argument to be parsed.
 * 
 * @author xsumnan on 29/03/2015.
 * 
 */
public class PkiCliCommand implements PkiCommand {

    private static final long serialVersionUID = 5140273685494829960L;

    private String commandText;

    private Map<String, Object> properties = new HashMap<>();

    public PkiCliCommand() {
    }

    public PkiCliCommand(final String commandText) {
        this.commandText = commandText;
    }

    public PkiCliCommand(final String commandText, final Map<String, Object> properties) {
        this.commandText = commandText;
        this.properties = properties;
    }

    /**
     * 
     * @return com.ericsson.itpf.security.pki.command line text provided
     */
    public String getCommandText() {
        return commandText;
    }

    /**
     * Sets com.ericsson.itpf.security.pki.command line text to be executed
     */
    public void setCommandText(final String commandText) {
        this.commandText = commandText;
    }

    /**
     * @return a Map with the associated additional properties of the com.ericsson.itpf.security.pki.command.
     */
    public Map<String, Object> getProperties() {
        return properties;
    }

    /**
     * Sets a Map with the properties that should be associated with this com.ericsson.itpf.security.pki.command
     * 
     * @param properties
     *            Map with additional properties of the com.ericsson.itpf.security.pki.command
     */
    public void setProperties(final Map<String, Object> properties) {
        this.properties = properties;
    }

    @Override
    public String toString() {
        return commandText;
    }
}
