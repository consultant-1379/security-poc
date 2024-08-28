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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.utils;

import java.io.InputStream;
import java.net.URL;

import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * This class is used for validating xml files with xsd for bulk import of profiles or entities and unmarshall the xml to Profiles or PKIEntities objects.
 * 
 */
public abstract class XSDValidator {
    /**
     * This method can be used to validate and unmarshall xml file containing Profiles.
     * 
     * @param xmlInputStream
     *            xml file should be sent as input stream.
     * @return Profiles object formed by unmarshalling the given input xml.
     * @throws CommonRuntimeException
     *             This exception is throw in case of failed xsd validation or error in unmarshalling.
     */
    public static Profiles profilesValidator(final InputStream xmlInputStream) throws CommonRuntimeException {

        final URL fileURL = Thread.currentThread().getContextClassLoader().getResource("/xsd/ProfilesSchema.xsd");
        final Profiles profiles = (Profiles) JaxbUtil.getObject(xmlInputStream, Profiles.class, fileURL);
        return profiles;
    }

    /**
     * This method can be used to validate and unmarshall xml file containing Entities.
     * 
     * @param xmlInputStream
     *            xml file should be sent as input stream.
     * @return Entities object formed by unmarshalling the given input xml.
     * @throws CommonRuntimeException
     *             This exception is throw in case of failed xsd validation or error in unmarshalling.
     */
    public static Entities entitiesValidator(final InputStream xmlInputStream) throws CommonRuntimeException {
        final URL fileURL = Thread.currentThread().getContextClassLoader().getResource("/xsd/EntitiesSchema.xsd");
        final Entities entities = (Entities) JaxbUtil.getObject(xmlInputStream, Entities.class, fileURL);
        return entities;
    }
}
