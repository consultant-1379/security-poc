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

import java.io.IOException;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

/**
 * A de-serializer for converting a JSON string of Entity Info to {@link EntityInfo} object.
 * 
 * @author tcspred
 * @version 1.2.4
 * 
 */
public class EntityInfoDeserializer extends JsonDeserializer<EntityInfo> {

    private final static String ID = "id";
    private final static String NAME = "name";
    private final static String SUBJECT = "subject";
    private final static String SUBJECT_ALT_NAME = "subjectAltName";
    private static final String OTP_COUNT = "oTPCount";
    private static final String OTP = "oTP";

    /**
     * Method to deserialize JSON content into the value type this serializer handles i.e., EntityInfo.
     * 
     * @param jsonParser
     *            Parser used for reading JSON content
     * @param context
     *            Context that can be used to access information about this deserialization activity
     * 
     * @return the deserialized EntityInfo object
     * 
     * @throws IOException
     *             when any I/O operation fails
     * @throws JsonProcessingException
     *             when any failure occurs in processing JSON content
     */
    @Override
    public EntityInfo deserialize(final JsonParser jsonParser, final DeserializationContext context) throws IOException, JsonProcessingException {
        final EntityInfo entityInfo = new EntityInfo();

        final ObjectCodec objectCodec = jsonParser.getCodec();
        final JsonNode jsonNode = objectCodec.readTree(jsonParser);
        final JsonNode idNode = jsonNode.get(ID);
        long id = 0;
        if (idNode != null && !idNode.isNull()) {
            id = idNode.asLong();
        }
        entityInfo.setId(id);
        final JsonNode nameNode = jsonNode.get(NAME);
        String name = null;
        if (nameNode != null && !nameNode.isNull()) {
            name = nameNode.asText();
        }
        entityInfo.setName(name);

        final JsonNode otpNode = jsonNode.get(OTP);
        String oTP = null;
        if (otpNode != null && !otpNode.isNull()) {
            oTP = otpNode.asText();
        }
        entityInfo.setOTP(oTP);

        final JsonNode otpCountNode = jsonNode.get(OTP_COUNT);
        int oTPCount = 0;
        if (otpCountNode != null && !otpCountNode.isNull()) {
            oTPCount = otpCountNode.asInt();
        }
        entityInfo.setOTPCount(oTPCount);

        final JsonNode subjectNode = jsonNode.get(SUBJECT);

        if (subjectNode != null && !subjectNode.isNull()) {
            final SubjectDeserializer subjectDeserializer = new SubjectDeserializer();
            final Subject subject = subjectDeserializer.deserialize(subjectNode);
            entityInfo.setSubject(subject);
        }

        final JsonNode subjectAltNameNode = jsonNode.get(SUBJECT_ALT_NAME);

        if (subjectAltNameNode != null && !subjectAltNameNode.isNull()) {
            final SubjectAltNameDeserializer subjectAltNameDeserializer = new SubjectAltNameDeserializer();
            final SubjectAltName subjectAltName = subjectAltNameDeserializer.deserialize(subjectAltNameNode);
            entityInfo.setSubjectAltName(subjectAltName);
        }

        return entityInfo;
    }
}
