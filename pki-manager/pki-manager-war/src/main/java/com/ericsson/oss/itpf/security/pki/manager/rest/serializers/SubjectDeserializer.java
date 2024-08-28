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

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.fasterxml.jackson.databind.JsonNode;

public class SubjectDeserializer {
    
    /**
     * Get Subject from JsonNode
     * 
     * @param subjectNode
     *          {@link JsonNode }
     * @return
     *  {@link Subject}
     */
    public Subject deserialize(final JsonNode subjectNode) {
        final Subject subject = new Subject();
        final JsonNode subjectFieldArray = subjectNode.get("subjectFields");

        if (subjectFieldArray.isArray()) {
            final Iterator<JsonNode> iterator = subjectFieldArray.elements();
            final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

            while (iterator.hasNext()) {
                final JsonNode subjectFieldNode = iterator.next();
                final SubjectField subjectField = new SubjectField();

                subjectField.setType(SubjectFieldType.fromName(subjectFieldNode.get("type").asText()));
                subjectField.setValue(subjectFieldNode.get("value").asText());

                subjectFields.add(subjectField);
            }
            subject.setSubjectFields(subjectFields);
        }
        return subject;
    }

}
