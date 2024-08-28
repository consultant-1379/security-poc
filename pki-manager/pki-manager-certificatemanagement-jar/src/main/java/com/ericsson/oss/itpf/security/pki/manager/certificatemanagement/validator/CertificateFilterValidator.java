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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

/**
 * Class for validating {@link CertificateFilter} fields.
 * 
 */
public class CertificateFilterValidator {

    /**
     * validating certificate filter for listing certificates thrown exception
     * when input is not matched
     * 
     * @param certificateFilter
     */
    public void validateCertificateFilter(final CertificateFilter certificateFilter) throws CertificateException {

        final Integer limit = certificateFilter.getLimit();
        final Integer offset = certificateFilter.getOffset();

        if (limit == null || offset == null) {
            throw new CertificateException(ErrorMessages.LIMIT_AND_OFFSET_MANDATORY);
        }
        if (offset == 0 && limit == 0) {
            throw new CertificateException(ErrorMessages.INVALID_LIMIT_AND_OFFSET);
        }
    }
}
