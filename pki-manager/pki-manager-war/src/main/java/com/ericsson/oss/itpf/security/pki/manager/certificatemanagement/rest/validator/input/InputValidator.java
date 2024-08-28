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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input;

import static com.ericsson.oss.itpf.security.pki.manager.rest.util.ErrorMessages.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.exception.InvalidArgumentException;

/**
 * Validates the Input in Rest Layer
 * 
 */
public class InputValidator {

    /**
     * validates filter for status and entity types
     * 
     * @param filterDTO
     *            The {@link FilterDTO}
     * @return return true/false when filter matches
     */
    public boolean validateFilterDTO(final FilterDTO filterDTO) {

        boolean isValidFilter = true;
        if (filterDTO != null) {
            if (validateNullFilter(filterDTO)) {
                return isValidFilter;
            }
            final CertificateStatus[] certificateStatus = filterDTO.getStatus();
            final EntityType[] entityTypes = filterDTO.getType();
            if ((certificateStatus == null || certificateStatus.length == 0) || (entityTypes == null || entityTypes.length == 0)) {
                isValidFilter = false;
                return isValidFilter;
            }
        }
        return isValidFilter;
    }

    /**
     * validates pagination, status and entity types for {@link CertificateDTO}
     * 
     * @param certificateDTO
     * @return return true/false when filter matches
     * @throws InvalidArgumentException
     *             throws Exception when limit and offset not given
     */
    public boolean validate(final CertificateDTO certificateDTO) throws InvalidArgumentException {

        validateOffsetAndLimit(certificateDTO.getLimit(), certificateDTO.getOffset());
        final boolean isValidFilter = validateFilterDTO(certificateDTO.getFilter());
        return isValidFilter;
    }

    /**
     * validates CertificateIds and Format for DownloadDTO
     * 
     * @param downloadDTO
     *            The {@link DownloadDTO}
     */
    public void validateDownloadDTO(final DownloadDTO downloadDTO) throws InvalidArgumentException {

        if (downloadDTO != null) {
            if (downloadDTO.getCertificateIds() == null || downloadDTO.getCertificateIds().length == 0) {
                throw new InvalidArgumentException(ErrorMessages.CERTIFICATE_ID_MANDATORY);
            }
            if (downloadDTO.getFormat() == null) {
                throw new InvalidArgumentException(ErrorMessages.CERTIFICATE_FILE_FORMAT_MANDATORY);
            }
        }
    }

    /**
     * Validates entityName,format and CSR.
     * 
     * @param keyStoreFileDTO
     *            The {@link KeyStoreFileDTO}
     * 
     * @throws InvalidArgumentException
     *             Throws in case of input argument is invalid.
     */
    public void validateFileDTO(final KeyStoreFileDTO keyStoreFileDTO) throws InvalidArgumentException {

        if (keyStoreFileDTO != null) {
            if (keyStoreFileDTO.getName() == null || keyStoreFileDTO.getName().isEmpty()) {
                throw new InvalidArgumentException(ENTITY_NAME_MANDATORY);
            }
            if (keyStoreFileDTO.getData() == null || keyStoreFileDTO.getData().isEmpty()) {
                throw new InvalidArgumentException(ErrorMessages.CSR_MANDATORY);
            }
            if (keyStoreFileDTO.getFormat() == null) {
                throw new InvalidArgumentException(FORMAT_NOT_SUPPORTED);
            }

        }

    }

    private void validateOffsetAndLimit(final Integer limit, final Integer offset) throws InvalidArgumentException {

        if (limit == null || offset == null) {
            throw new InvalidArgumentException(ErrorMessages.LIMIT_AND_OFFSET_MANDATORY);
        }
        if (offset == 0 && limit == 0) {
            throw new InvalidArgumentException(ErrorMessages.INVALID_LIMIT_AND_OFFSET);
        }
    }

    private boolean validateNullFilter(final FilterDTO filterDTO) {

        if (filterDTO == null) {
            return true;
        }
        return filterDTO.getExpiryDateFrom() == null && filterDTO.getExpiryDateTo() == null && filterDTO.getIssuer() == null && filterDTO.getStatus() == null && filterDTO.getSubject() == null
                && filterDTO.getType() == null;
    }

    /**
     * Validates CAName and Re-issueType.
     * 
     * @param caReissueDTO
     *            The {@link CAReissueDTO}
     * 
     * @throws InvalidArgumentException
     *             Throws in case of input argument is invalid.
     */
    public void validateCAReissueDTO(final CAReissueDTO caReissueDTO) throws InvalidArgumentException {

        if (caReissueDTO != null) {
            if (caReissueDTO.getName() == null || caReissueDTO.getName().isEmpty()) {
                throw new InvalidArgumentException(CA_NAME_MANDATORY);
            }
            if (caReissueDTO.getReIssueType() == null) {
                throw new InvalidArgumentException(com.ericsson.oss.itpf.security.pki.manager.rest.util.ErrorMessages.RE_ISSUE_TYPE_MANDATORY);
            }
        }
    }

    /**
     * Validates entity name and format.
     * 
     * @param entityReissueDTO
     *            The {@link EntityReissueDTO}
     * 
     * @throws InvalidArgumentException
     *             Throws in case of input argument is invalid.
     */
    public void validateEntityReissueDTO(final EntityReissueDTO entityReissueDTO) throws InvalidArgumentException {

        if (entityReissueDTO != null) {
            if (entityReissueDTO.getName() == null || entityReissueDTO.getName().isEmpty()) {
                throw new InvalidArgumentException(END_ENTITY_NAME_MANDATORY);
            }
            if (entityReissueDTO.getFormat() == null) {
                throw new InvalidArgumentException(FORMAT_NOT_SUPPORTED);
            }
        }
    }
}
