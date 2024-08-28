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

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class EntityInfoFetchSerializer extends JsonSerializer<EntityInfo> {

    private final static String ID = "id";
    private final static String NAME = "name";
    private final static String STATUS = "status";
    private final static String SUBJECT = "subject";
    private final static String SUBJECT_ALT_NAME = "subjectAltName";
    private static final String OTP_COUNT = "otpcount";
    private static final String OTP = "otp";
    private static final String CERTIFICATE_ASSIGNED = "certificateAssigned";

    /**
     * Method to serialize values of type this serializer handles. i.e., EntityInfo.
     * 
     * @param entityInfo
     *            entity info in JSON string that should be serialized
     * @param generator
     *            Generator used to output resulting Json content
     * @param provider
     *            Provider that can be used to get serializers for serializing Objects value contains, if any.
     * 
     * @throws IOException
     *             when any I/O operation fails
     * @throws JsonProcessingException
     *             when any failure occurs in processing JSON content
     */
    public void serialize(final EntityInfo entityInfo, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {
        generator.writeStartObject();

        generator.writeNumberField(ID, entityInfo.getId());
        generator.writeStringField(NAME, entityInfo.getName());
        generator.writeNumberField(OTP_COUNT, entityInfo.getOTPCount());
        generator.writeStringField(OTP, entityInfo.getOTP());
        generator.writeStringField(STATUS, entityInfo.getStatus().value());

        generator.writeFieldName(SUBJECT);
        generator.writeObject(entityInfo.getSubject());

        generator.writeFieldName(SUBJECT_ALT_NAME);
        generator.writeObject(entityInfo.getSubjectAltName());

        int certificatesAssigned = entityInfo.getInActiveCertificates().size();

        if (entityInfo.getActiveCertificate() != null) {
            certificatesAssigned += 1;
        }

        generator.writeNumberField(CERTIFICATE_ASSIGNED, certificatesAssigned);

        generator.writeEndObject();
    }
}
