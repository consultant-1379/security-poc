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
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;

/**
 * This class is used to validate External CAs for a {@link TrustProfile}
 * 
 * 
 */
public class ExternalCAsValidator implements CommonValidator<TrustProfile> {

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

        validateCAs(trustProfile.getExternalCAs());
    }

    /**
     * Validate given lsit of names of internal CAs i.e {@link CAEntity} are valid or not.
     * 
     * @param externalCAs
     *            {@link java.util.List} of {@link java.lang.String}
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws CANotFoundException
     *             thrown when given {@link CAEntity} doesn't exists or in revoked state
     * 
     */
    private void validateCAs(final List<ExtCA> externalCAs) throws CANotFoundException, ExternalCredentialMgmtServiceException {
        logger.debug("Validating Internal CAs {}", externalCAs);
        if (externalCAs.isEmpty()) {
            logger.debug("Trust Profile doesn't contain external CA");
            return;
        }

        validateExternalCAs(externalCAs);

    }

    private void validateExternalCAs(final List<ExtCA> externalCAs) throws CANotFoundException, ExternalCredentialMgmtServiceException {
        Set<CAEntityData> externalCADataSet = null;
        final List<String> externalCANames = new ArrayList<String>();
        for (final ExtCA extCA : externalCAs) {
            externalCANames.add(extCA.getCertificateAuthority().getName());
        }
        final Set<String> externalCANameSet = new HashSet<String>(externalCANames);

        if (externalCAs.size() != 0) {
            try {
                externalCADataSet = new HashSet<CAEntityData>(persistenceManager.findEntityIN(CAEntityData.class, externalCANames, NAME_PATH_IN_CA));
            } catch (final PersistenceException e) {
                logger.error("SQL Exception occurred while checking CAs in DB {}", e.getMessage());
                throw new ExternalCredentialMgmtServiceException(Constants.OCCURED_IN_VALIDATING, e);
            }

            for (final Iterator<CAEntityData> iterator = externalCADataSet.iterator(); iterator.hasNext();) {
                final CAEntityData externalCA = iterator.next();
                if (externalCA.isExternalCA()) {
                    externalCANameSet.remove(externalCA.getCertificateAuthorityData().getName());
                }
            }

            if (!externalCANameSet.isEmpty()) {
                logger.error("Given CA(s): {} , Not found in in DB.", externalCANameSet);
                throw new CANotFoundException(Constants.GIVEN_EXTERNAL_CA + externalCANameSet + ProfileServiceErrorCodes.ERR_NOT_FOUND_OR_INACTIVE);
            }
        }
    }

}
