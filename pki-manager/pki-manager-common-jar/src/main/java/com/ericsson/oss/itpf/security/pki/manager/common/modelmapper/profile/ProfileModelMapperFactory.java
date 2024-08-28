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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;


/**
 * Model Mapper Factory used to get the instance of proper Profile Mapper out of Entity/Trust/Certificate Profile Mappers and also CAENtity/Entity Mappers..
 *
 */
public class ProfileModelMapperFactory {

    @Inject
    @ProfileQualifier(ProfileType.TRUST_PROFILE)
    ModelMapper trustprofileMapper;

    @Inject
    @ProfileQualifier(ProfileType.CERTIFICATE_PROFILE)
    ModelMapper certificateProfileMapper;

    @Inject
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    ModelMapper entityProfileMapper;

    @Inject
    CertificateProfileExportMapper certProfileExportMapper;

    @Inject
    EntityProfileExportMapper entityProfileExportMapper;

    @Inject
    TrustProfileExportMapper trustProfileExportMapper;

    /**
     * The method to get the appropriate {@link ModelMapper} instance based on {@link ProfileType}.
     *
     * @param profileType
     * @return Instance of {@link ModelMapper}
     */
    public ModelMapper getProfileModelMapper(final ProfileType profileType) throws InvalidProfileException {

        ModelMapper modelMapper = null;

        switch (profileType) {

        case TRUST_PROFILE:
            modelMapper = trustprofileMapper;
            break;
        case ENTITY_PROFILE:
            modelMapper = entityProfileMapper;
            break;
        case CERTIFICATE_PROFILE:
            modelMapper = certificateProfileMapper;
            break;
        default:
            throw new InvalidProfileException(ProfileServiceErrorCodes.INVALID_PROFILE_TYPE);
        }
        return modelMapper;
    }

    /**
     * This method will return the appropriate {@link ModelMapper} instance which returns profiles used for Import/update Profiles Operation based on
     * {@link ProfileType}.
     *
     * @param profileType
     * @return Instance of {@link ModelMapper}
     * @throws InvalidProfileException
     */
    public ModelMapper getProfileExportModelMapper(final ProfileType profileType) throws InvalidProfileException {

        ModelMapper modelMapper = null;

        switch (profileType) {

        case TRUST_PROFILE:
            modelMapper = trustProfileExportMapper;
            break;
        case ENTITY_PROFILE:
            modelMapper = entityProfileExportMapper;
            break;
        case CERTIFICATE_PROFILE:
            modelMapper = certProfileExportMapper;
            break;
        default:
            throw new InvalidProfileException(ProfileServiceErrorCodes.INVALID_PROFILE_TYPE);
        }
        return modelMapper;
    }

}