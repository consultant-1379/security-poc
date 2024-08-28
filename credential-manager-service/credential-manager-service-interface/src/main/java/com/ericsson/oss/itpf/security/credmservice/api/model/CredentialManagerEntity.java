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
//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2015.03.03 at 04:45:34 PM IST
//

package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;

public class CredentialManagerEntity extends CredentialManagerAbstractEntity implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 4053830746674212222L;

    /**
     * 
     */
    public CredentialManagerEntity() {
        entityType = CredentialManagerEntityType.ENTITY;
        entityStatus = CredentialManagerEntityStatus.NEW;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        final StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append(" EndEntity:[ ");
        stringBuffer.append(" Name: " + name);
        stringBuffer.append(" Id: " + id);
        stringBuffer.append(" Subject: " + subject);
        stringBuffer.append(" SubjectAltName: " + subjectAltName);
        stringBuffer.append(" EntityProfileName: " + entityProfileName);
        stringBuffer.append(" keyGenerationAlgorithm: " + keyGenerationAlgorithm);
        stringBuffer.append(" EntityStatus: " + entityStatus + " ] ");
        return stringBuffer.toString();
    }
}
