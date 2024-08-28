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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameValueCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

/**
 * 
 * This class will add the Entity profiles information in PkiNameValueCommandResponse object.
 * 
 * @author tcschsa
 */
public class EntityProfileViewCommandResponse {

    @Inject
    private Logger logger;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    private static final String ENTITY_PROFILE_DATA = "Entity Profile Data::";
    private static final String SUBJECT_ALT_NAME = "Subject Alt Name: ";
    private static final String KEY_GENERATION_ALGORITHM = "Key Generation Algorithm: ";
    private static final String EXTENDED_KEY_USAGE_EXTENSION = "Extended Key Usage Extension: ";
    private static final String KEY_USAGE_EXTENSION = "Key Usage Extension: ";
    private static final String TRUST_PROFILE = "Trust Profile: ";
    private static final String CERTIFICATE_PROFILE = "Certificate Profile: ";
    private static final String SUBJECT_UNIQUE_IDENTIFIER_VALUE = "SubjectUniqueIdentifierValue: ";

    /**
     * Method to build the command response for viewing the Entity profile data
     *
     * @param entityProfile
     * @return PkiNameValueCommandResponse
     *
     */
    public PkiNameValueCommandResponse buildCommandResponseForEntityProfile(final EntityProfile entityProfile) {

        final PkiNameValueCommandResponse commandResponse = new PkiNameValueCommandResponse();

        commandResponse.add(ENTITY_PROFILE_DATA, Constants.EMPTY_STRING);
        commandResponse.add(Constants.NAME_VIEW, (null != entityProfile.getName() ? entityProfile.getName() : Constants.EMPTY_STRING));
        commandResponse.add(Constants.IS_ACTIVE, ValidationUtils.isTrueOrFalse(entityProfile.isActive()));
        commandResponse.add(Constants.MODIFIABLE_VIEW, ValidationUtils.isTrueOrFalse(entityProfile.isModifiable()));
        commandResponse.add(Constants.PROFILE_VALIDITY, (null != entityProfile.getProfileValidity() ? commandHandlerUtils.getDateString(entityProfile.getProfileValidity()) : Constants.EMPTY_STRING));
        commandResponse.add(Constants.SUBJECT, (null != entityProfile.getSubject() ? commandHandlerUtils.getAllSubjectFields(entityProfile.getSubject()) : Constants.EMPTY_STRING));
        commandResponse.add(SUBJECT_ALT_NAME, (null != entityProfile.getSubjectAltNameExtension() ? commandHandlerUtils.getAllSubjectAltNameFields(entityProfile.getSubjectAltNameExtension())
                : Constants.EMPTY_STRING));
        commandResponse.add(KEY_GENERATION_ALGORITHM,
                (null != entityProfile.getKeyGenerationAlgorithm() ? commandHandlerUtils.getKeyGenerationAlgorithmString(entityProfile.getKeyGenerationAlgorithm()) : Constants.EMPTY_STRING));
        commandResponse.add(EXTENDED_KEY_USAGE_EXTENSION, (null != entityProfile.getExtendedKeyUsageExtension() ? getExtendedKeyUsageList(entityProfile.getExtendedKeyUsageExtension())
                : Constants.EMPTY_STRING));
        commandResponse.add(KEY_USAGE_EXTENSION, (null != entityProfile.getKeyUsageExtension() ? getKeyUsageList(entityProfile.getKeyUsageExtension()) : Constants.EMPTY_STRING));
        commandResponse.add(TRUST_PROFILE, getTrustProfileList(entityProfile.getTrustProfiles()));
        commandResponse.add(CERTIFICATE_PROFILE, entityProfile.getCertificateProfile().getName());
        commandResponse.add(SUBJECT_UNIQUE_IDENTIFIER_VALUE, (null != entityProfile.getSubjectUniqueIdentifierValue() ? entityProfile.getSubjectUniqueIdentifierValue() : Constants.EMPTY_STRING));
        return commandResponse;

    }

    private String getTrustProfileList(final List<TrustProfile> trustProfiles) {

        if (ValidationUtils.isNullOrEmpty(trustProfiles)) {
            return Constants.EMPTY_STRING;
        }

        final List<String> trustProfileNames = new ArrayList<>();
        for (final TrustProfile trustProfile : trustProfiles) {
            trustProfileNames.add(trustProfile.getName());
        }
        return CommandHandlerUtils.getFieldValues(trustProfileNames, Constants.COMMA);
    }

    private final String getKeyUsageList(final KeyUsage keyUsageExtension) {
        final List<KeyUsageType> keyUsageTypes = keyUsageExtension.getSupportedKeyUsageTypes();
        return CommandHandlerUtils.getFieldValues(keyUsageTypes, Constants.COMMA);
    }

    private String getExtendedKeyUsageList(final ExtendedKeyUsage extendedkeyUsageExtension) {
        final List<KeyPurposeId> keyPurposeIds = extendedkeyUsageExtension.getSupportedKeyPurposeIds();
        return CommandHandlerUtils.getFieldValues(keyPurposeIds, Constants.COMMA);
    }

}
