/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.CAReissueDTO;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

/**
 * A de-serializer for converting a JSON string of CAReissueInfo to {@link CAReissueDTO} object.
 * 
 * @author xbensar
 * 
 */
public class CAReissueDesializer extends JsonDeserializer<CAReissueDTO> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAReissueDesializer.class);

    private final static String NAME = "name";
    private final static String REVOCATIONREASON = "revocationReason";
    private final static String REISSUETYPE = "reIssueType";
    private final static String REKEY = "rekey";

    /**
     * Method to deserialize JSON content into the value type this serializer handles i.e., CAReissueDTO.
     * 
     * @param jsonParser
     *            Parser used for reading JSON content
     * @param context
     *            Context that can be used to access information about this deserialization activity
     * 
     * @return the deserialized CAReissueDTO object
     * 
     * @throws IOException
     *             when any I/O operation fails
     * @throws JsonProcessingException
     *             when any failure occurs in processing JSON content
     */
    @Override
    public CAReissueDTO deserialize(final JsonParser jsonParser, final DeserializationContext context) throws IOException, JsonProcessingException {
        final CAReissueDTO caReissueDTO = new CAReissueDTO();

        final ObjectCodec objectCodec = jsonParser.getCodec();
        final JsonNode jsonNode = objectCodec.readTree(jsonParser);

        final JsonNode nameNode = jsonNode.get(NAME);
        String name = null;
        if (nameNode != null && !nameNode.isNull()) {
            name = nameNode.asText();
        }
        caReissueDTO.setName(name);

        final JsonNode otpNode = jsonNode.get(REVOCATIONREASON);
        if (otpNode!= null && !otpNode.isNull()) {
            try {
                caReissueDTO.setRevocationReason(RevocationReason.fromValue(otpNode.asText()));
            } catch (final IllegalArgumentException ie) {
                int revocationReason;
                revocationReason = otpNode.asInt();
                caReissueDTO.setRevocationReason(RevocationReason.getNameByValue(revocationReason));
                LOGGER.debug("Illegal Argument Exception occured ", ie);
            }

        }

        final JsonNode reIssueTypeNode = jsonNode.get(REISSUETYPE);
        String reIssueType = null;
        if (reIssueTypeNode != null && !reIssueTypeNode.isNull()) {
            reIssueType = reIssueTypeNode.asText();
        }

        caReissueDTO.setReIssueType(ReIssueType.valueOf(reIssueType));

        final JsonNode rekeyNode = jsonNode.get(REKEY);
        boolean rekey = false;
        if (rekeyNode != null && !rekeyNode.isNull()) {
            rekey = rekeyNode.asBoolean();
        }

        caReissueDTO.setRekey(rekey);
        return caReissueDTO;
    }
}
