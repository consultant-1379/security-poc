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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

/**
 * A FilterMapper class for convert the filterDTO and certificateDTO objects into CertificateFilter object To apply the filter and get the certificates.
 */
public class FilterMapper {

    /**
     * Converts the {@link FilterDTO} to {@link CertificateFilter} object
     * 
     * @param filterDTO
     *            Object containing certificateIds,subject,expiryDateFrom,expiryDateTo,issuer,type and status.
     * 
     * @return the certificateFilter Object containing certificateIds,subjectDN,expiryDateFrom,expiryDateTo,issuerDN,entityTypes,certificateStatus,offset and limit.
     * 
     */
    public CertificateFilter toCertificateFilter(final FilterDTO filterDTO) {

        final CertificateFilter certificateFilter = new CertificateFilter();
        if (filterDTO != null) {
            if (filterDTO.getSubject() != null && !filterDTO.getSubject().isEmpty()) {
                certificateFilter.setSubjectDN(filterDTO.getSubject());
            }
            if (filterDTO.getIssuer() != null && !filterDTO.getIssuer().isEmpty()) {
                certificateFilter.setIssuerDN(filterDTO.getIssuer());
            }
            if (filterDTO.getType() != null && filterDTO.getType().length > 0) {
                certificateFilter.setEntityTypes(filterDTO.getType());
            }
            if (filterDTO.getStatus() != null && filterDTO.getStatus().length > 0) {
                certificateFilter.setCertificateStatusList(filterDTO.getStatus());
            }
            certificateFilter.setExpiryDateFrom(filterDTO.getExpiryDateFrom());
            certificateFilter.setExpiryDateTo(filterDTO.getExpiryDateTo());
        } else {
            certificateFilter.setEntityTypes(EntityType.values());
        }
        return certificateFilter;
    }

    /**
     * Converts the {@link CertificateDTO} to {@link CertificateFilter} object
     * 
     * @param certificateDTO
     *            Object containing filterDTO,offset and limit.
     * 
     * @return the certificateFilter Object containing certificateIds,subjectDN,expiryDateFrom,expiryDateTo,issuerDN,entityTypes,certificateStatus,offset and limit.
     * 
     */
    public CertificateFilter toCertificateFilter(final CertificateDTO certificateDTO) {

        CertificateFilter certificateFilter = null;
        if (certificateDTO != null) {
            certificateFilter = toCertificateFilter(certificateDTO.getFilter());
            certificateFilter.setOffset(certificateDTO.getOffset());
            certificateFilter.setLimit(certificateDTO.getLimit());
        }
        return certificateFilter;
    }

    /**
     * Converts the {@link FilterDTO} to {@link CertificateFilter} object for Certificate Load.
     * 
     * @param filterDTO
     *            Object containing certificate id's.
     * 
     * @return the certificateFilter Object containing certificate id's and offset and limit.
     * 
     */
    public CertificateFilter toCertificateFilterForLoad(final Long[] certificateIds) {

        final CertificateFilter certificateFilter = new CertificateFilter();
        if (certificateIds != null && certificateIds.length > 0) {
            certificateFilter.setCertificateIdList(certificateIds);
            certificateFilter.setOffset(0);
            certificateFilter.setLimit(certificateIds.length);
        }
        return certificateFilter;
    }

    /**
     * Converts the {@link DownloadDTO} to {@link CertificateFilter} object
     * 
     * @param DownloadDTO
     *            Object containing certificateIds, extension type.
     * 
     * @return the certificateFilter Object containing certificateIds, offset and limit.
     * 
     */
    public CertificateFilter toCertificateFilter(final DownloadDTO downloadDTO) {

        final CertificateFilter certificateFilter = new CertificateFilter();
        if (downloadDTO != null) {
            certificateFilter.setCertificateIdList(downloadDTO.getCertificateIds());
            certificateFilter.setOffset(0);
            certificateFilter.setLimit(downloadDTO.getCertificateIds().length);
        }
        return certificateFilter;
    }
}
