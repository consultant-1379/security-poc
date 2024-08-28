/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.util.PkiObjectSelector;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

public class CredMServiceCAEntityUpdate {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceCAEntityUpdate.class);

    /**
     * @param xmlCAEntity
     * @param pkiCAEntity
     */
    public static CAEntity updateCvn_0(final CAEntity... CAEntities) {

        CAEntity pkiCAEntity = null;
        CAEntity xmlCAEntity = null;

        xmlCAEntity = CAEntities[0];

        pkiCAEntity = (CAEntity) PkiObjectSelector.getPkiObject(CAEntities);

        if (pkiCAEntity == null) {
            return null;
        }
        if ((pkiCAEntity.getCertificateAuthority().getCrlGenerationInfo() == null ||
                pkiCAEntity.getCertificateAuthority().getCrlGenerationInfo().isEmpty())
                && xmlCAEntity.getCertificateAuthority().getCrlGenerationInfo() != null &&
                !xmlCAEntity.getCertificateAuthority().getCrlGenerationInfo().isEmpty()) {

            log.info("updateCAEntityCvn_0 : pkiCAEntity = " + pkiCAEntity.getCertificateAuthority().getName()
                    + " ... Updating Crl Generation Info ...");

            pkiCAEntity.getCertificateAuthority().setCrlGenerationInfo(
                    xmlCAEntity.getCertificateAuthority().getCrlGenerationInfo());
            pkiCAEntity.getCertificateAuthority().setPublishToCDPS(xmlCAEntity.getCertificateAuthority().isPublishToCDPS());

            return pkiCAEntity;
        }
        return null;
    }

}
