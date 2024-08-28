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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * A Utility class for get the certificate details like subjectAltName,entityTypes,cRLDistributionPoints and keyUsages.
 */
public class CertificateUtil {

    /**
     * Get the subjectAltName value from the Certificate
     * 
     * @param subjectAltName
     *            object
     * 
     * @return the subjectAltName string
     * 
     */
    public String getSubjectAltName(final SubjectAltName subjectAltName) {

        StringBuilder san = new StringBuilder("");

        if (subjectAltName.getSubjectAltNameFields().isEmpty()) {
            return san.toString();
        }

        for (final SubjectAltNameField subjectAltNameField : subjectAltName.getSubjectAltNameFields()) {

            if (subjectAltNameField.getValue() instanceof SubjectAltNameString) {
                final SubjectAltNameString subjectAltNameString = (SubjectAltNameString) subjectAltNameField.getValue();
                san = san.append(subjectAltNameField.getType().name() + ":" + subjectAltNameString.getValue() + ",");
            } else if (subjectAltNameField.getValue() instanceof EdiPartyName) {
                final EdiPartyName ediPartyName = (EdiPartyName) subjectAltNameField.getValue();
                san = san.append(subjectAltNameField.getType().name() + ":" + ediPartyName.getNameAssigner() + " " + ediPartyName.getPartyName() + ",");
            } else {
                final OtherName otherName = (OtherName) subjectAltNameField.getValue();
                san = san.append(subjectAltNameField.getType().name() + ":" + otherName.getTypeId() + " " + otherName.getValue() + ",");

            }
        }
        return san.substring(0, (san.length()) - 1);
    }

    /**
     * Get the Entity type whether certificate belongs to Entity or CAEntity
     * 
     * @param certificate
     *            pathLengthConstarint
     * 
     * @return the {@link EntityType} Object
     * 
     */
    public EntityType getEntityType(final int pathLengthConstarint) {

        EntityType entityType = null;

        if (pathLengthConstarint < 0) {
            entityType = EntityType.ENTITY;
        } else {
            entityType = EntityType.CA_ENTITY;
        }

        return entityType;

    }

    /**
     * Get the keyUsages of certificate
     * 
     * @param keyUsages
     * 
     * @return the {@link keyUsages} list
     * 
     */
    public List<KeyUsageType> getKeyUsage(final boolean[] keyUsages) {

        int id = 0;
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        if (keyUsages == null) {
            return keyUsageTypes;
        }
        for (final boolean keyUsage : keyUsages) {

            if (keyUsage) {
                keyUsageTypes.add(KeyUsageType.fromId(id));
            }
            id++;

        }
        return keyUsageTypes;
    }
}
