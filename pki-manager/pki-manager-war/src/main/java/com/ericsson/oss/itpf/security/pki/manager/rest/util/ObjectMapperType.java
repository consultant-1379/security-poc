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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Enum containing different types of JSON {@link ObjectMapper} that are available.
 * 
 * @author xnagcho
 * @version 1.2.4
 */
public enum ObjectMapperType {
    COMMON_MAPPER, ACCESS_METHOD_MAPPER, KEY_PURPOSE_ID_MAPPER, CERTIFICATE_MAPPER, KEY_USAGE_TYPE_MAPPER, EXTENDED_KEY_USAGE_TYPE_MAPPER, REASON_FLAGS_MAPPER, SUBJECT_ALT_NAME_TYPE_MAPPER, ERROR_MESSAGE_MAPPER, TRUST_PROFILE_SERIALIZER_MAPPER, TRUST_PROFILE_DESERIALIZER_MAPPER, TRUSTED_CA_MAPPER, SUBJECT_FIELD_TYPE_MAPPER, ENTITY_PROFILE_MAPPER, KEY_GEN_ALGORITHM_SEIALIZER_MAPPER, SUBJECT_ALT_NAME_EXTENSION_MAPPER, SUBJECT_CAPABILITIES_MAPPER, ENTITY_CATEGORY_MAPPER, ENTITY_MAPPER, ENTITY_PROFILE_FETCH_MAPPER, ENTITY_FETCH_MAPPER, ENTITY_DESERIALIZER_MAPPER, CA_ENTITY_FETCH_MAPPER, CA_ENTITY_DESERIALIZER_MAPPER, ENTITIES_FETCH_MAPPER, CERTIFICATE_MODEL_MAPPER, CERTIFICATE_DATE_MAPPER, PROFILES_FETCH_MAPPER, REVOCATION_REASON_DESERIALIZER_MAPPER, CAENTITY_REISSUE_MAPPER, ENTITY_REISSUE_MAPPER, REISSUE_WITH_CSR_MAPPER, ISSUER_ID_NAME_MAPPER, CERTIFICATE_PROFILE_ID_NAME_MAPPER, TRUST_PROFILE_ID_NAME_MAPPER, REVOCATION_REASON_MAPPER;
}
