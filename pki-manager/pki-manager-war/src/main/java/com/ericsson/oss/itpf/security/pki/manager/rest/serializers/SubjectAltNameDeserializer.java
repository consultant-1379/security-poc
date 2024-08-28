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
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.fasterxml.jackson.databind.JsonNode;

public class SubjectAltNameDeserializer {
    
 
    /**
     * Get SubjectAltName from JsonNode
     * 
     * @param subjectAltNameNode
     *          {@link JsonNode }
     * @return
     *  {@link SubjectAltName}
     */
    public SubjectAltName deserialize(final JsonNode subjectAltNameNode) {
        final SubjectAltName subjectAltName = new SubjectAltName();
        final JsonNode criticalNode = subjectAltNameNode.get("critical");
        final JsonNode subjectAltNameFieldArray = subjectAltNameNode.get("subjectAltNameFields");

        if (criticalNode !=null && !criticalNode.isNull()) {
            subjectAltName.setCritical(criticalNode.asBoolean());
        }

        if (subjectAltNameFieldArray != null && subjectAltNameFieldArray.isArray()) {
            final Iterator<JsonNode> iterator = subjectAltNameFieldArray.elements();
            final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

            while (iterator.hasNext()) {
                final JsonNode subjectAltNameFieldNode = iterator.next();
                final JsonNode abstractSubjectAltNameFieldValueNode = subjectAltNameFieldNode.get("value");
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();

                subjectAltNameField.setType(SubjectAltNameFieldType.fromName(subjectAltNameFieldNode.get("type").asText()));

                final String subjectAltNameFieldValueClass = abstractSubjectAltNameFieldValueNode.get("@class").asText();

                if (subjectAltNameFieldValueClass.equals(".OtherName")) {
                    final OtherName otherName = new OtherName();

                    otherName.setTypeId(abstractSubjectAltNameFieldValueNode.get("typeId").asText());
                    otherName.setValue(abstractSubjectAltNameFieldValueNode.get("value").asText());

                    subjectAltNameField.setValue(otherName);
                } else if (subjectAltNameFieldValueClass.equals(".EdiPartyName")) {
                    final EdiPartyName ediPartyName = new EdiPartyName();

                    ediPartyName.setNameAssigner(abstractSubjectAltNameFieldValueNode.get("nameAssigner").asText());
                    ediPartyName.setPartyName(abstractSubjectAltNameFieldValueNode.get("partyName").asText());

                    subjectAltNameField.setValue(ediPartyName);
                } else if (subjectAltNameFieldValueClass.equals(".SubjectAltNameString")) {
                    final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();

                    subjectAltNameString.setValue(abstractSubjectAltNameFieldValueNode.get("value").asText());

                    subjectAltNameField.setValue(subjectAltNameString);
                }

                subjectAltNameFields.add(subjectAltNameField);
            }
            subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        }
        return subjectAltName;
    }

}
