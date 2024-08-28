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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.serializers.CertificateDateSerializer;
import com.ericsson.oss.itpf.security.pki.manager.common.IssuerMixIn;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ErrorMessageDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;

/**
 * A utility class to load the JSON ObjectMappers at startup.
 * 
 * @author xnagcho
 * @version 1.2.4
 * 
 */
@Singleton
public class ObjectMapperUtil {

    @Inject
    private Logger logger;

    private ObjectMapper commonMapper, accessMethodMapper, keyPurposeIdMapper, certificateMapper, keyUsageTypeMapper, extendedKeyUsageTypeMapper, reasonFlagsMapper, subjectAltNameFieldTypeMapper,
            errorMessageMapper, trustProfileSerializerMapper, trustProfileDeserializerMapper, trustedCAMapper, subjectFieldTypeMapper, entityProfileMapper, entityProfileFetchMapper,
            keyGenerationAlgorithmSerializerMapper, subjectAltNameExtensionMapper, subjectCapabilitiesMapper, entitiesFetchMapper, entityCategoryMapper, entityFetchMapper, entityDeserializerMapper,
            caEntityFetchMapper, caEntityDeserializerMapper, certificateModelMapper, profilesFetchMapper, revocationReasonDeserializerMapper, caentityReissueMapper, entityReissueMapper,
            reissueWithCSRMapper, issuerFetchMapper, certificateProfileFetchMapper, trustProfileFetchMapper, revocationReasonMapper;

    private final static String INVALID_MAPPER_TYPE = "Invalid mapper type!";

    @PostConstruct
    void startup() throws IOException {
        commonMapper = getCommonMapper();
        accessMethodMapper = getAccessMethodMapper();
        keyPurposeIdMapper = getKeyPurposeIdMapper();
        certificateMapper = getCertificateMapper();
        keyUsageTypeMapper = getKeyUsageMapper();
        extendedKeyUsageTypeMapper = getExtendedKeyUsageMapper();
        reasonFlagsMapper = getReasonFlagsMapper();
        subjectAltNameFieldTypeMapper = getSubjectAltNameFieldTypeMapper();
        errorMessageMapper = getErrorMessageMapper();
        trustProfileSerializerMapper = getTrustProfileSerializerMapper();
        trustProfileDeserializerMapper = getTrustProfileDeserializerMapper();
        trustedCAMapper = getTrustedCAMapper();
        subjectFieldTypeMapper = getSubjectFieldTypeMapper();
        entityProfileMapper = getEntityProfileMapper();
        keyGenerationAlgorithmSerializerMapper = getKeyGenerationAlgorithmSerializerMapper();
        subjectAltNameExtensionMapper = getSubjectAltNameExtensionMapper();
        subjectCapabilitiesMapper = getSubjectCapabilitiesMapper();
        entitiesFetchMapper = getEntitiesFetchMapper();
        entityCategoryMapper = getEntityCategoryMapper();
        entityProfileFetchMapper = getEntityProfileFetchMapper();
        entityFetchMapper = getEntityFetchMapper();
        entityDeserializerMapper = getEntityDeserializerMapper();
        caEntityFetchMapper = getCAEntityFetchMapper();
        caEntityDeserializerMapper = getCAEntityDeserializerMapper();
        certificateModelMapper = getCertficateModelSerializerMapper();
        profilesFetchMapper = getProfilesFetchMapper();
        revocationReasonDeserializerMapper = getRevocationReasonDeserializerMapper();
        caentityReissueMapper = getCAEntityReissueMapper();
        entityReissueMapper = getEntityReissueMapper();
        reissueWithCSRMapper = getReissueWithCSRMapper();
        certificateProfileFetchMapper = getCertificateProfileFetchMapper();
        trustProfileFetchMapper = getTrustProfileFetchMapper();
        issuerFetchMapper = getIssuerFetchMapper();
        revocationReasonMapper = getRevocationReasonMapper();
    }

    private ObjectMapper getCommonMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        return mapper;
    }

    private ObjectMapper getAccessMethodMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod.class,
                new EnumTypeSerializer<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getKeyPurposeIdMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId.class,
                new EnumTypeSerializer<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getCertificateMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getKeyUsageMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType.class,
                new EnumTypeSerializer<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getExtendedKeyUsageMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId.class,
                new EnumTypeSerializer<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getReasonFlagsMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag.class,
                new EnumTypeSerializer<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getSubjectAltNameFieldTypeMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType.class,
                new EnumTypeSerializer<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getSubjectAltNameExtensionMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType.class,
                new EnumTypeSerializerWithoutId<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getErrorMessageMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(ErrorMessageDTO.class, new ErrorMessagesSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getTrustProfileSerializerMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(TrustProfile.class, new TrustProfileSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getTrustProfileDeserializerMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(TrustProfile.class, new TrustProfileDeserializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getTrustedCAMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(CAEntity.class, new TrustedCASerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getSubjectFieldTypeMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(SubjectFieldType.class, new EnumTypeSerializer<SubjectFieldType>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getSubjectCapabilitiesMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(SubjectFieldType.class, new EnumTypeSerializerWithoutId<SubjectFieldType>());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getEntityProfileMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(TrustProfile.class, new AbstractProfileSerializer());
        module.addSerializer(CAEntity.class, new IssuerSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getEntityProfileFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(EntityProfile.class, new AbstractProfileSerializer());
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getKeyGenerationAlgorithmSerializerMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(Algorithm.class, new KeyGenerationAlgorithmSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getEntitiesFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        module.addSerializer(EntityInfo.class, new EntityInfoFetchSerializer());
        module.addSerializer(CertificateAuthority.class, new CertificateAuthorityFetchSerializer());
        module.addSerializer(EntityProfile.class, new AbstractProfileSerializer());

        mapper.registerModule(module);
        return mapper;
    }

    private ObjectMapper getCAEntityDeserializerMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(CertificateAuthority.class, new CertificateAuthorityDeserializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getCAEntityFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        mapper.addMixInAnnotations(CertificateProfile.class, IssuerMixIn.class);

        module.addSerializer(CertificateAuthority.class, new CertificateAuthoritySerializer());
        module.addSerializer(TrustProfile.class, new AbstractProfileSerializer());
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getEntityCategoryMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(EntityCategory.class, new EntityCategorySerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getEntityFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(EntityInfo.class, new EntityInfoSerializer());
        module.addSerializer(TrustProfile.class, new AbstractProfileSerializer());
        module.addSerializer(CAEntity.class, new IssuerSerializer());
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getEntityDeserializerMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(EntityInfo.class, new EntityInfoDeserializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getCertficateModelSerializerMapper() {

        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(Date.class, new CertificateDateSerializer());

        mapper.registerModule(module);
        return mapper;
    }

    private ObjectMapper getProfilesFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(AbstractProfile.class, new AbstractProfileFetchSerializer());

        mapper.registerModule(module);
        return mapper;
    }

    private ObjectMapper getRevocationReasonDeserializerMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(RevocationReason.class, new RevocationReasonDeserializer());

        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getCAEntityReissueMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(CAReissueDTO.class, new CAReissueDesializer());
        mapper.registerModule(module);
        return mapper;
    }

    private ObjectMapper getEntityReissueMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(EntityReissueDTO.class, new EntityReissueDeSerializer());
        mapper.registerModule(module);
        return mapper;
    }

    private ObjectMapper getReissueWithCSRMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addDeserializer(KeyStoreFileDTO.class, new ReissueWithCSRDeSerializer());
        mapper.registerModule(module);
        return mapper;
    }

    private ObjectMapper getCertificateProfileFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(CertificateProfile.class, new AbstractProfileSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getTrustProfileFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(TrustProfile.class, new AbstractProfileSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getIssuerFetchMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(CertificateAuthority.class, new IssuerFetchSerializer());
        mapper.registerModule(module);

        return mapper;
    }

    private ObjectMapper getRevocationReasonMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(RevocationReason.class, new RevocationReasonSerializer());

        mapper.registerModule(module);

        return mapper;
    }

    /**
     * Serialize the Basic Details and Extension details of Certificate object and ignore the specified fields in serialization for JSON object
     * 
     * @param detailsFilterProperties
     *            and extensionsFilterProperties to be applied for non serialization process in certificate list JSON response
     * 
     * @return serialized {@link ObjectWriter} writer object
     * 
     */
    public ObjectWriter getCertficateSerializerMapper(final Set<String> detailsFilterProperties, final Set<String> extensionsFilterProperties) {

        certificateModelMapper = getObjectMapper(ObjectMapperType.CERTIFICATE_MODEL_MAPPER);

        final FilterProvider filterProvider = new SimpleFilterProvider().addFilter("certificate", SimpleBeanPropertyFilter.serializeAllExcept(new HashSet<String>()))
                .addFilter("details", SimpleBeanPropertyFilter.serializeAllExcept(detailsFilterProperties))
                .addFilter("extensions", SimpleBeanPropertyFilter.serializeAllExcept(extensionsFilterProperties));

        return certificateModelMapper.writer(filterProvider);
    }

    /**
     * Serialize the Basic Details of Certificate object and ignore the specified fields in serialization for JSON object
     * 
     * @param detailsFilterProperties
     *            to be applied for non serialization process in certificate list JSON response
     * 
     * @return serialized {@link ObjectWriter} writer object
     * 
     */
    public ObjectWriter getCertficateSerializerMapper(final Set<String> detailsFilterProperties) {

        certificateModelMapper = getObjectMapper(ObjectMapperType.CERTIFICATE_MODEL_MAPPER);

        final FilterProvider filterProvider = new SimpleFilterProvider().addFilter("details", SimpleBeanPropertyFilter.serializeAllExcept(detailsFilterProperties));

        return certificateModelMapper.writer(filterProvider);
    }

    /**
     * Get {@link ObjectMapper} with registered serialize modules based on type.
     * 
     * @param objectMapperType
     *            Type of object mapper required.
     * @return instance of {@link ObjectMapper}
     */
    public ObjectMapper getObjectMapper(final ObjectMapperType objectMapperType) {
        switch (objectMapperType) {
        case ACCESS_METHOD_MAPPER:
            return accessMethodMapper;
        case CERTIFICATE_MAPPER:
            return certificateMapper;
        case COMMON_MAPPER:
            return commonMapper;
        case KEY_PURPOSE_ID_MAPPER:
            return keyPurposeIdMapper;
        case KEY_USAGE_TYPE_MAPPER:
            return keyUsageTypeMapper;
        case EXTENDED_KEY_USAGE_TYPE_MAPPER:
            return extendedKeyUsageTypeMapper;
        case REASON_FLAGS_MAPPER:
            return reasonFlagsMapper;
        case SUBJECT_ALT_NAME_TYPE_MAPPER:
            return subjectAltNameFieldTypeMapper;
        case ERROR_MESSAGE_MAPPER:
            return errorMessageMapper;
        case TRUST_PROFILE_SERIALIZER_MAPPER:
            return trustProfileSerializerMapper;
        case TRUST_PROFILE_DESERIALIZER_MAPPER:
            return trustProfileDeserializerMapper;
        case TRUSTED_CA_MAPPER:
            return trustedCAMapper;
        case SUBJECT_FIELD_TYPE_MAPPER:
            return subjectFieldTypeMapper;
        case ENTITY_PROFILE_MAPPER:
            return entityProfileMapper;
        case ENTITY_PROFILE_FETCH_MAPPER:
            return entityProfileFetchMapper;
        case KEY_GEN_ALGORITHM_SEIALIZER_MAPPER:
            return keyGenerationAlgorithmSerializerMapper;
        case SUBJECT_ALT_NAME_EXTENSION_MAPPER:
            return subjectAltNameExtensionMapper;
        case SUBJECT_CAPABILITIES_MAPPER:
            return subjectCapabilitiesMapper;
        case ENTITY_CATEGORY_MAPPER:
            return entityCategoryMapper;
        case ENTITY_DESERIALIZER_MAPPER:
            return entityDeserializerMapper;
        case ENTITIES_FETCH_MAPPER:
            return entitiesFetchMapper;
        case CA_ENTITY_FETCH_MAPPER:
            return caEntityFetchMapper;
        case ENTITY_FETCH_MAPPER:
            return entityFetchMapper;
        case CA_ENTITY_DESERIALIZER_MAPPER:
            return caEntityDeserializerMapper;
        case CERTIFICATE_MODEL_MAPPER:
            return certificateModelMapper;
        case PROFILES_FETCH_MAPPER:
            return profilesFetchMapper;
        case REVOCATION_REASON_DESERIALIZER_MAPPER:
            return revocationReasonDeserializerMapper;
        case CAENTITY_REISSUE_MAPPER:
            return caentityReissueMapper;
        case ENTITY_REISSUE_MAPPER:
            return entityReissueMapper;
        case REISSUE_WITH_CSR_MAPPER:
            return reissueWithCSRMapper;
        case CERTIFICATE_PROFILE_ID_NAME_MAPPER:
            return certificateProfileFetchMapper;
        case TRUST_PROFILE_ID_NAME_MAPPER:
            return trustProfileFetchMapper;
        case ISSUER_ID_NAME_MAPPER:
            return issuerFetchMapper;
        case REVOCATION_REASON_MAPPER:
            return revocationReasonMapper;
        default:
            logger.error(INVALID_MAPPER_TYPE);
            throw new IllegalArgumentException(INVALID_MAPPER_TYPE);
        }
    }
}
