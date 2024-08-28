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

import java.util.LinkedHashMap;
import java.util.Map;

import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;

/**
 * <p>
 * It is basis for any com.ericsson.itpf.security.pki.command in the PKI component. It consists of a PkiCommandType and all properties needed to perform the actual
 * com.ericsson.itpf.security.pki.command execution.
 * </p>
 * <p>
 * Ideally this class should be specialized in order to add convenience methods for needed parameters.
 * </p>
 * 
 * 
 * @author xsumnan on 29/03/2015.
 */
public class PkiPropertyCommand implements PkiCommand {

    private static final long serialVersionUID = -8755949165090394109L;

    public static final String COMMAND_TYPE_PROPERTY = "command";

    private PkiCommandType commandType;
    private Map<String, Object> properties = new LinkedHashMap<>();

    /**
     * @return returns the com.ericsson.itpf.security.pki.command type to be executed by PKI-manager component
     */
    public PkiCommandType getCommandType() {
        return commandType;
    }

    /**
     * Sets the com.ericsson.itpf.security.pki.command type to be executed by PKI-manager component
     */
    public void setCommandType(final PkiCommandType commandType) {
        this.commandType = commandType;
    }

    /**
     * @return a Map containing properties needed by the com.ericsson.itpf.security.pki.command handler in order to perform it's actions
     */
    public Map<String, Object> getProperties() {
        return properties;
    }

    /**
     * Sets a Map containing properties needed by the com.ericsson.itpf.security.pki.command handler in order to perform it's actions
     */
    public void setProperties(final Map<String, Object> properties) {
        this.properties = properties;
    }

    /**
     * Convenience method to facilitate access to a property value by subclasses
     * 
     * @param property
     *            - name of the property
     * @return the Object associated with the property name or null
     */
    protected Object getValue(final String property) {
        return getProperties().get(property);
    }

    /**
     * Convenience method to facilitate update of a property value by subclasses
     * 
     * @param property
     *            property name to be included or updated
     * @param value
     *            new value of the property
     */
    protected void setValue(final String property, final Object value) {
        getProperties().put(property, value);
    }

    /**
     * Convenience method to facilitate access to a property value by subclasses
     * 
     * @param property
     *            - name of the property
     * @return a String representation of the value or null if there is no property for the provided name
     */
    public String getValueString(final String property) {
        final Object value = getValue(property);
        return value == null ? null : value.toString();
    }

    /**
     * Convenience method to facilitate access to a property value by subclasses
     * 
     * @param property
     *            property name to be included or updated
     * @param value
     *            new value of the property. If value is not null, value.toString() will be called before insertion into the property Map.
     */
    protected void setValueString(final String property, final Object value) {
        setValue(property, value == null ? null : value.toString());
    }

    /**
     * Convenience method to check if the given property exists in the property Map
     * 
     * @param property
     *            name of the property
     * @return true if Properties Map contains a property with the given name
     */
    public boolean hasProperty(final String property) {
        return this.properties.containsKey(property);
    }

    public static boolean isPkiAdmCommand(final PkiCommand command) {
        return PkiPropertyCommand.class.isAssignableFrom(command.getClass());
    }

    @Override
    public String toString() {
        return String.format("type = %s, properties = %s", commandType, properties);
    }
}
