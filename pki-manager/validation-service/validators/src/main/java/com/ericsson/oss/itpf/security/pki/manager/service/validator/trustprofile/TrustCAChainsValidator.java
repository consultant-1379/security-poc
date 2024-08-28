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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;

/**
 * This class is used to validate internalCA's for a {@link TrustProfile}.
 * 
 * 
 */
public class TrustCAChainsValidator implements CommonValidator<TrustProfile> {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;
    private final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final TrustProfile trustProfile) throws ValidationException {

        validateTrustCAChain(trustProfile.getTrustCAChains());
    }

    /**
     * Validate given list of names of internal CAs i.e {@link CAEntity} are valid or not.
     * 
     * @param internalCAs
     *            {@link java.util.List} of {@link java.lang.String}
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws CANotFoundException
     *             thrown when given {@link CAEntity} doesn't exists or in revoked state
     * 
     */
    private void validateTrustCAChain(final List<TrustCAChain> trustCAChains) throws CANotFoundException, ProfileServiceException {
        logger.debug("Validating Internal CAs {}", trustCAChains);

        if (ValidationUtils.isNullOrEmpty(trustCAChains)) {
            logger.debug("Trust Profile must contain atleast one internal CA");
            return;
        }

        validateInternalCAs(trustCAChains);
    }

    private void validateInternalCAs(final List<TrustCAChain> trustCAChains) throws CANotFoundException, ProfileServiceException {
        final Set<String> internalCANameSet = new HashSet<String>();
        Set<CAEntityData> internalCADataSet = null;

        for (final TrustCAChain trustCAChain : trustCAChains) {
            final CAEntity internalCA = trustCAChain.getInternalCA();
            if (internalCA != null && internalCA.getCertificateAuthority() != null) {
                final String internalCAName = internalCA.getCertificateAuthority().getName();
                if (internalCANameSet.contains(internalCAName)) {
                    throw new InvalidProfileAttributeException("Duplicate Internal CAs given");
                } else {
                    internalCANameSet.add(internalCAName);
                }
            } else {
                throw new InvalidProfileAttributeException("Invalid CA Entity Specified");
            }
        }

        if (internalCANameSet.size() != 0) {
            try {
                internalCADataSet = new HashSet<CAEntityData>(persistenceManager.findEntityIN(CAEntityData.class, internalCANameSet, NAME_PATH_IN_CA));
            } catch (final PersistenceException e) {
                logger.error("SQL Exception occurred while checking CAs in DB {}", e.getMessage());
                throw new ProfileServiceException(Constants.OCCURED_IN_VALIDATING, e);
            }

            for (final Iterator<CAEntityData> iterator = internalCADataSet.iterator(); iterator.hasNext();) {
                final CAEntityData internalCA = iterator.next();
                if (!internalCA.isExternalCA()) {
                    internalCANameSet.remove(internalCA.getCertificateAuthorityData().getName());
                }
            }

            if (!internalCANameSet.isEmpty()) {
                logger.error("Given CA(s): {} , Not found in in DB.", internalCANameSet);
                throw new CANotFoundException(Constants.GIVEN_INTERNAL_CA + internalCANameSet + ProfileServiceErrorCodes.ERR_NOT_FOUND_OR_INACTIVE);
            }
        }
    }

}
