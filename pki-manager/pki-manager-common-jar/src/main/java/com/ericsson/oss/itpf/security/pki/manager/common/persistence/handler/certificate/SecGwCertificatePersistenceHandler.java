/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * This class is responsible for getting subject field types from entity profile for secgw
 *
 * @author xlakdag
 *
 */
public class SecGwCertificatePersistenceHandler {

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Inject
    Logger logger;

    /**
     * To get subject field types from entity profile based on given profile name
     *
     * @param profileName
     *            the name of the entity profile
     * @return Set of Subject Field Types from Entity Profile
     * @throws CANotFoundException
     *             thrown when the issuer CA not found
     * @throws InvalidProfileAttributeException
     *             thrown when profile attribute is invalid
     * @throws InvalidProfileException
     *             thrown when profile is not valid
     * @throws MissingMandatoryFieldException
     *             thrown when mandatory field is missed in profile
     * @throws ProfileNotFoundException
     *             thrown when Profile not found
     * @throws ProfileServiceException
     *             thrown when any internal error occurs in system.
     */
    public Set<SubjectFieldType> getSubjectFieldTypes(final String profileName) throws CANotFoundException,
            InvalidProfileAttributeException, InvalidProfileException, MissingMandatoryFieldException, ProfileNotFoundException,
            ProfileServiceException {
        List<SubjectField> subjectFields = null;

        final ProfilePersistenceHandler<EntityProfile> profilePersistenceHandler = (ProfilePersistenceHandler<EntityProfile>) profilePersistenceHandlerFactory
                .getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE);

        final EntityProfile inputProfile = new EntityProfile();
        inputProfile.setName(profileName);
        final EntityProfile entityProfile = profilePersistenceHandler.getProfile(inputProfile);

        if (entityProfile == null) {
            logger.error("Entity Profile {} is not found.", profileName);
            throw new ProfileNotFoundException("Entity Profile is not found.");
        }
        subjectFields = entityProfile.getSubject().getSubjectFields();
        final Set<SubjectFieldType> subjectFieldTypes = new HashSet<SubjectFieldType>();

        for (final SubjectField subjectField : subjectFields) {
            subjectFieldTypes.add(subjectField.getType());
        }
        return subjectFieldTypes;
    }
}
