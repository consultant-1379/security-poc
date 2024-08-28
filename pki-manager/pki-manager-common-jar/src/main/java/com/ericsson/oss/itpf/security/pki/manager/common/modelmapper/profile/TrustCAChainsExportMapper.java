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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;


/**
 * This class is used to map TrustCAChain from JPA Entity to API Model with only required fields used for Import TrustProfile operation.
 *
 * @author xsusant
 */
public class TrustCAChainsExportMapper {
    @Inject
    private Logger logger;

    /**
     * This method Converts {@link TrustCAChainData} to {@link TrustCAChain}
     *
     * @param dataModel
     *            Instance of {@link TrustCAChainData}
     * @return Instance of {@link TrustCAChain}
     */
    public <T, E> T toAPIFromModel(final E dataModel) {
        final TrustCAChainData trustCAChainData = (TrustCAChainData) dataModel;

        final CAEntity internalCA = issuerToAPIFromModel(trustCAChainData.getCAEntity());
        final boolean isChainRequired = trustCAChainData.isChainRequired();

        final TrustCAChain trustCAChain = new TrustCAChain();
        trustCAChain.setChainRequired(isChainRequired);
        trustCAChain.setInternalCA(internalCA);
        return (T) trustCAChain;
    }

    private CAEntity issuerToAPIFromModel(final CAEntityData caEntityData) {

        if (caEntityData == null) {
            return null;
        }

        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());

        caEntity.setCertificateAuthority(certificateAuthority);

        logger.debug("Mapped CAEntity domain model is {}", caEntity);

        return caEntity;
    }

}
