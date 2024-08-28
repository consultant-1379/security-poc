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

package com.ericsson.itpf.security.pki.cmdhandler.parser.antlr;

import java.util.*;

/**
 * <b>Class used by the com.ericsson.itpf.security.pki.command parser to store expected com.ericsson.itpf.security.pki.command properties.</b>
 * Created by xsumnan on 28/05/2014.
 * 
 * 
 * Be aware that this class is used by src/main/g4/com/ericsson/itpf/security/pki/parser/PkiBaseParser.g4 file
 * careful is required when changing it.
 * */

/**
 * 
 * @author xsumnan on 29/03/2015.
 */

public class ValidProperties {

    private final Map<String, String> aliasToArg = new HashMap();
    private final Map<String, String> types = new HashMap();

    /**
     * Checks if property is available or not.
     * 
     * @param propertyOrAlias
     * @return <code>true</code> or <code>false</code>
     */

    public boolean contains(final String propertyOrAlias) {
        return aliasToArg.containsKey(propertyOrAlias);
    }

    /**
     * Method for getting Property by type
     * 
     * @param propertyOrAlias
     * @return {@link String}
     */
    public String getPropertyType(final String propertyOrAlias) {
        return types.get(propertyOrAlias);
    }

    /**
     * Method for getting targeted property
     * 
     * @param propertyOrAlias
     * @return String
     */
    public String getTargetProperty(final String propertyOrAlias) {
        return aliasToArg.get(propertyOrAlias);
    }

    /**
     * Method for getting valid properties and aliases
     * 
     * @return
     */
    public Set<String> getValidPropertyOrAliases() {
        return aliasToArg.keySet();
    }

    /**
     * Method to fetch arguments from properties
     * 
     * @param spec
     * @return
     */
    public static ValidProperties fromArgSpec(final Object... spec) {
        if (spec == null) {
            return null;
        }

        final ValidProperties properties = new ValidProperties();
        Collection<?> argAndAlises;
        for (Object arg : spec) {
            if (arg instanceof Collection) {
                Property mainArg = null;
                Property candidate = null;
                argAndAlises = (Collection<?>) arg;
                for (Object argOrAlias : argAndAlises) {
                    candidate = addAndGetProperty(argOrAlias.toString(), mainArg, properties);
                    if (mainArg == null) {
                        mainArg = candidate;
                    }
                }
            } else {
                addAndGetProperty(arg.toString(), null, properties);
            }
        }

        return properties;
    }

    private static Property addAndGetProperty(final String argText, final Property mainProp, final ValidProperties properties) {
        final String[] parts = argText.split(":");
        final Property prop = new Property();
        prop.name = parts[0];
        prop.type = parts.length > 1 ? parts[1] : null;

        if (!prop.name.startsWith("-")) {
            throw new IllegalArgumentException(String.format("Illegal name '%s', it should start with '-'", prop.name));
        }

        final String defaultType = mainProp == null ? null : mainProp.type;
        final String destArg = mainProp == null ? null : mainProp.name;

        properties.types.put(prop.name, prop.type == null ? defaultType : prop.type);
        properties.aliasToArg.put(prop.name, destArg == null ? prop.name : destArg);

        return prop;
    }

    private static class Property {
        public String name;
        public String type;
    }
}
