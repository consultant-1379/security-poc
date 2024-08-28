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

import static com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.Constants.ENTITY_REISSUE_PASSPHRASE;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityReissueDTO;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

/**
 * A de-serializer for converting a JSON string of Entity Reissue DTO to {@link EntityReissueDTO} object.
 * 
 * @author xbensar
 * 
 */
public class EntityReissueDeSerializer extends JsonDeserializer<EntityReissueDTO> {

    private static final Logger LOGGER = LoggerFactory.getLogger(EntityReissueDeSerializer.class);
    private static final String NAME = "name";
    private static final String REVOCATIONREASON = "revocationReason";
    private static final String FORMAT = "format";
    private static final String CHAIN = "chain";

    /**
     * Method to deserialize JSON content into the value type this serializer handles i.e., EntityReissueDTO.
     * 
     * @param jsonParser
     *            Parser used for reading JSON content
     * @param context
     *            Context that can be used to access information about this deserialization activity
     * 
     * @return the deserialized EntityReissueDTO object
     * 
     * @throws IOException
     *             when any I/O operation fails
     * @throws JsonProcessingException
     *             when any failure occurs in processing JSON content
     */
    @Override
    public EntityReissueDTO deserialize(final JsonParser jsonParser, final DeserializationContext context) throws IOException, JsonProcessingException {
        final EntityReissueDTO entityReissueDTO = new EntityReissueDTO();

        final ObjectCodec objectCodec = jsonParser.getCodec();
        final JsonNode jsonNode = objectCodec.readTree(jsonParser);

        final JsonNode nameNode = jsonNode.get(NAME);
        String name = null;
        if (nameNode != null && !nameNode.isNull()) {
            name = nameNode.asText();
        }
        entityReissueDTO.setName(name);

        final JsonNode otpNode = jsonNode.get(REVOCATIONREASON);
        if (otpNode != null && !otpNode.isNull()) {
            try {
                entityReissueDTO.setRevocationReason(RevocationReason.fromValue(otpNode.asText()));
            } catch (final IllegalArgumentException ie) {
                int revocationReason;
                revocationReason = otpNode.asInt();
                entityReissueDTO.setRevocationReason(RevocationReason.getNameByValue(revocationReason));
                LOGGER.debug("Illegal Argument Exception occured ", ie);
            }

        }

        final JsonNode formatNode = jsonNode.get(FORMAT);
        String format = null;
        if (formatNode != null && !formatNode.isNull()) {
            format = formatNode.asText();
        }

        entityReissueDTO.setFormat(KeyStoreType.valueOf(format));

        final JsonNode chainNode = jsonNode.get(CHAIN);
        boolean chain = false;
        if (chainNode != null && !chainNode.isNull()) {
            chain = chainNode.asBoolean();
        }

        entityReissueDTO.setChain(chain);

        final JsonNode passwordNode = jsonNode.get(ENTITY_REISSUE_PASSPHRASE);
        String password = null;
        if (passwordNode != null && !passwordNode.isNull()) {
            password = passwordNode.asText();
        }

        entityReissueDTO.setPassword(password);

        return entityReissueDTO;
    }
}
