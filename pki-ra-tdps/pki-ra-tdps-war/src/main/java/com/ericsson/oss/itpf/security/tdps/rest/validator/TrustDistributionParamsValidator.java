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
package com.ericsson.oss.itpf.security.tdps.rest.validator;

import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.errormessage.ErrorMessage;
import com.ericsson.oss.itpf.security.tdps.rest.exceptions.*;

/**
 * This is a validator class whihc validates the input parameters i.e path parameters whether they are NULL or not. Or whether entityType and certificateStatus are not of valid type.
 * 
 * @author tcsdemi
 *
 */
public class TrustDistributionParamsValidator {

    /**
     * This method validates input parameters for null and invalid entityType and certificate status type
     * 
     * @param trustDistributionParameters
     */
    public void validate(final TrustDistributionParameters trustDistributionParameters) throws InvalidEntityException, InvalidCertificateStatusException, MissingMandatoryParamException {
        verifyForNullParams(trustDistributionParameters);
        verifyValidParams(trustDistributionParameters);
    }

    private void verifyValidParams(final TrustDistributionParameters trustDistributionParameters) throws InvalidEntityException, InvalidCertificateStatusException {
        if (!(trustDistributionParameters.getEntityType().equalsIgnoreCase(TDPSEntity.CA_ENTITY.getValue()) || (trustDistributionParameters.getEntityType().equalsIgnoreCase(TDPSEntity.ENTITY
                .getValue())))) {
            throw new InvalidEntityException(ErrorMessage.ERR_INVALID_ENTITY_TYPE);
        }

        if (!((trustDistributionParameters.getCertificateStatus().equalsIgnoreCase(TDPSCertificateStatus.ACTIVE.getValue())) || (trustDistributionParameters.getCertificateStatus().equalsIgnoreCase(TDPSCertificateStatus.INACTIVE.getValue())))) {
            throw new InvalidCertificateStatusException(ErrorMessage.ERR_INVALID_CERTIFICATE_STATUS_TYPE);
        }

    }

    private void verifyForNullParams(final TrustDistributionParameters trustDistributionParameters) throws MissingMandatoryParamException {
        if (trustDistributionParameters.getCertificateSerialId() == null) {
            throw new MissingMandatoryParamException(ErrorMessage.ERR_NULL_CERTIFICATE_ID);
        }

        if (trustDistributionParameters.getEntityName() == null) {
            throw new MissingMandatoryParamException(ErrorMessage.ERR_NULL_ENTITY_NAME);
        }

        if (trustDistributionParameters.getIssuerName() == null) {
            throw new MissingMandatoryParamException(ErrorMessage.ERR_NULL_ISSUER_NAME);
        }

        if (trustDistributionParameters.getCertificateStatus() == null) {
            throw new MissingMandatoryParamException(ErrorMessage.ERR_NULL_CERTIFICATE_STATUS);
        }

        if (trustDistributionParameters.getEntityType() == null) {
            throw new MissingMandatoryParamException(ErrorMessage.ERR_NULL_ENTITY_TYPE);
        }
    }
}