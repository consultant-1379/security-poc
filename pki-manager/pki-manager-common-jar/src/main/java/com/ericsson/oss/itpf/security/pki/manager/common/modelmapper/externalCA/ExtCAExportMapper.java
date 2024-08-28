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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

/**
 * This class is used to map ExtCA from JPA Entity to API Model with only required fields used for Import TrustProfile operation.
 *
 * @author xsusant
 */
public class ExtCAExportMapper {

    @Inject
    private Logger logger;

    /**
     * Maps the CA Entity JPA model to its corresponding API model used for Export profile/(s) operation.
     *
     * @param entityData
     *            CAEntityData Object which should be converted to API model CAEntity
     *
     * @throws ExternalCRLEncodedException
     *             Thrown when the CRL is not correct.
     *
     * @return Returns the API model of the given JPA model
     */
    public <T, E> T toAPIFromModel(final E entityData) throws ExternalCRLEncodedException {

        final CAEntityData caEntityData = (CAEntityData) entityData;

        logger.debug("Mapping CAEntityData entity {} to CAEntity domain model.", caEntityData.getId());
        final CertificateAuthority certificateAuthority = externalCAtoAPIFromModelCertAuth(caEntityData);

        final ExtCA extCA = new ExtCA();
        extCA.setCertificateAuthority(certificateAuthority);
        return (T) extCA;
    }

    private CertificateAuthority externalCAtoAPIFromModelCertAuth(final CAEntityData caEntityData) {
        if (caEntityData == null) {
            return null;
        }

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();
        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());
        certificateAuthority.setSubjectAltName(toSubjectAltName(certificateAuthorityData.getSubjectAltName()));
        certificateAuthority.setRootCA(certificateAuthorityData.isRootCA());
        certificateAuthority.setStatus(CAStatus.getStatus(certificateAuthorityData.getStatus()));
        certificateAuthority.setPublishToCDPS(certificateAuthorityData.isPublishToCDPS());
        return certificateAuthority;
    }

    private SubjectAltName toSubjectAltName(final String subjectAltNameString) {
        if (!ValidationUtils.isNullOrEmpty(subjectAltNameString)) {
            return JsonUtil.getObjectFromJson(SubjectAltName.class, subjectAltNameString);
        }
        return null;
    }

}
