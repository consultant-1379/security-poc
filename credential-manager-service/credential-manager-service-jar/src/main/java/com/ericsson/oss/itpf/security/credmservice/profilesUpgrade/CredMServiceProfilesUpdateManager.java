/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.profilesUpgrade;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceCAEntityUpdate;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceCertificateProfileUpdate;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceEntityProfileUpdate;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceTrustProfileUpdate;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

@Stateless
public class CredMServiceProfilesUpdateManager {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceProfilesUpdateManager.class);

    List<CustomConfiguration> listCustomConfigurations;

    CustomConfigurations credMCustomConfigurations = null;
    CustomConfigurations pkiCustomConfigurations = null;

    @Inject
    private SystemRecorderWrapper systemRecorder;
    private final String className = this.getClass().getSimpleName();

    @Inject
    CredMServiceCustomConfigurationManagementHandler credMServiceCustomConfigurationManagementHandler;

    private boolean cvnIsEgual = false;
    private Integer pkiCvn = 0;
    private Integer credMCvn = 0;

    boolean initDone = false;

    public boolean isInitDone() {
        log.info("CredMServiceHierarchyConfiguratorVersionUpdate flag is: {}", initDone);
        return initDone;
    }

    /**
     * Called in order to init pki and credm related CVN variables..
     */

    public void init() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {

        log.info("Running cvn-init");

        credMCustomConfigurations = credMServiceCustomConfigurationManagementHandler.getCredMServiceCustomConfigurations();

        if (credMCustomConfigurations == null) {
            systemRecorder.recordError("CustomConfigurationInvalidException thrown", ErrorSeverity.ERROR, className,
                    "CVN configuration numbers reading on credm was not possible to perform!", null);
            throw new CustomConfigurationInvalidException("CVN configuration numbers reading on credm was not possible to perform!!");
        }
        credMCvn = getValue("cvn", credMCustomConfigurations);

        log.info("credCustomConfigurations value is: cvn={}", credMCvn);

        pkiCvn = readPkiCvn();

        log.info("pkiCustomConfigurations value is: cvn={}", pkiCvn);

        if (pkiCvn == credMCvn) {
            cvnIsEgual = true;
        } else if (pkiCvn < credMCvn) {
            cvnIsEgual = false;
        } else { // pkiCvn > credMCvn, it cannot be allowed
            systemRecorder.recordError("CustomConfigurationInvalidException thrown", ErrorSeverity.ERROR, className,
                    "CVN configuration numbers on Pki database are bigger than the ones on CredM configuration property!", null);
            throw new CustomConfigurationInvalidException(
                    "CVN configuration numbers on Pki database are bigger than the ones on CredM configuration property!");
        }

        log.info("found cvn flag are {} equal", cvnIsEgual ? " " : "not ");

        initDone = true;
    }

    public boolean readAndCompareCvn() throws CustomConfigurationInvalidException, CustomConfigurationServiceException {

        boolean compareCvnValues = false;

        if (!initDone) {
            log.info("called readAndCompareCvn without performing init...");
            return false;
        }

        final Integer readCurrentPkiCvn = readPkiCvn();

        if (readCurrentPkiCvn == credMCvn && readCurrentPkiCvn != pkiCvn) {
            compareCvnValues = true;
        }

        log.warn("readAndCompareCvn result is: {} readCurrentPkiCvn is: {} pkiPreviousCvn is: {} credCvn is {}", compareCvnValues, readCurrentPkiCvn,
                pkiCvn, credMCvn);

        return compareCvnValues;

    }

    /**
     *
     */

    private Integer readPkiCvn() {

        Integer readPkiCvn = 0;

        try {
            pkiCustomConfigurations = credMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations();
        } catch (CustomConfigurationNotFoundException | CustomConfigurationInvalidException | CustomConfigurationServiceException e) {
            log.error("credMServiceCustomConfigurationManagementHandler: " + e.getMessage());
        }
        if (pkiCustomConfigurations == null) {
            log.warn("pkiCustomConfigurations is not present , setting default values..may be it is the first time ?");
        } else {
            readPkiCvn = getValue("cvn", pkiCustomConfigurations);
        }

        return readPkiCvn;
    }

    /**
     * @param xmlCertificateProfile
     * @param pkiCertificateProfile
     * @return certificateProfile (
     */

    public CertificateProfile checkCertificateProfileUpgradePath(final CertificateProfile xmlCertificateProfile,
                                                                 final CertificateProfile pkiCertificateProfile) {
        log.info("Checking upgradePath for CertificateProfile: " + pkiCertificateProfile.getName());

        CertificateProfile certificateProfile = null;
        if (!cvnIsEgual) {
            switch (pkiCvn) {
                case 0:

                    certificateProfile = CredMServiceCertificateProfileUpdate.updateCvn_0(xmlCertificateProfile, pkiCertificateProfile,
                            certificateProfile);
                    certificateProfile = CredMServiceCertificateProfileUpdate.updateCvn_1(xmlCertificateProfile, pkiCertificateProfile,
                            certificateProfile);
                    break;
                case 1:

                    certificateProfile = CredMServiceCertificateProfileUpdate.updateCvn_1(xmlCertificateProfile, pkiCertificateProfile,
                            certificateProfile);
                    break;
                case 2:
                case 3:

                default:
                    break;

            }

        }
        return certificateProfile;
    }

    /**
     * @param xmlTrustProfile
     * @param pkiTrustProfile
     * @return trustProfile
     */

    public TrustProfile checkTrustProfileUpgradePath(final TrustProfile xmlTrustProfile, final TrustProfile pkiTrustProfile) {
        log.info("Checking upgradePath for TrustProfile: " + pkiTrustProfile.getName());

        TrustProfile trustProfile = null;
        if (!cvnIsEgual) {
            switch (pkiCvn) {
                case 0:

                    trustProfile = CredMServiceTrustProfileUpdate.updateCvn_0(xmlTrustProfile, pkiTrustProfile, trustProfile);
                    trustProfile = CredMServiceTrustProfileUpdate.updateCvn_3(xmlTrustProfile, pkiTrustProfile, trustProfile);
                    break;
                case 1:

                case 2:
                case 3:

                    trustProfile = CredMServiceTrustProfileUpdate.updateCvn_3(xmlTrustProfile, pkiTrustProfile, trustProfile);
                    break;
                default:
                    break;
            }
        }
        return trustProfile;
    }

    /**
     * @param xmlEntityProfile
     * @param pkiEntityProfile
     * @return entityProfile
     */

    public EntityProfile checkEntityProfileUpgradePath(final EntityProfile xmlEntityProfile, final EntityProfile pkiEntityProfile) {
        log.info("Checking upgradePath for EntityProfile: " + pkiEntityProfile.getName());

        EntityProfile entityProfile = null;

        if (!cvnIsEgual) {

            switch (pkiCvn) {
                case 0:

                case 1:

                case 2:

                    entityProfile = CredMServiceEntityProfileUpdate.updateCvn_2(xmlEntityProfile, pkiEntityProfile, entityProfile);
                    break;
                case 3:
                default:
                    break;

            }

        }
        return entityProfile;

    }

    /**
     * @param xmlCAEntity
     * @param pkiCAEntity
     * @return CAEntity
     */

    public CAEntity checkCAEntityUpgradePath(final CAEntity xmlCAEntity, final CAEntity pkiCAEntity) {
        log.info("Checking upgradePath for CAEntity: " + pkiCAEntity.getCertificateAuthority().getName());

        CAEntity caEntity = null;
        if (!cvnIsEgual) {
            switch (pkiCvn) {
                case 0:

                    caEntity = CredMServiceCAEntityUpdate.updateCvn_0(xmlCAEntity, pkiCAEntity, caEntity);
                    break;
                case 1:

                case 2:

                case 3:

                default:
                    break;
            }
        }
        return caEntity;
    }

    public void updatePkiCustomConfigurations()
            throws CustomConfigurationInvalidException, CustomConfigurationServiceException, CustomConfigurationAlreadyExistsException {

        if (cvnIsEgual) {
            log.info("Called upgrade pki CustomConfigurations but it is not necessary to perform such operation");
        } else {
            if (initDone) {
                credMServiceCustomConfigurationManagementHandler.setPkiCustomConfigurationsUpdate(credMCustomConfigurations);
            } else {
                log.error("Called upgrade pki CustomConfigurations without credM CustomConfigurations reading");
            }
        }

    }

    private Integer getValue(final String name, final CustomConfigurations customConfigurations) {

        for (Integer i = 0; i < customConfigurations.getCustomConfigurations().size(); i++) {
            final CustomConfiguration customConfiguration = customConfigurations.getCustomConfigurations().get(i);

            log.debug("customConfiguration.getName() {} name:{}", customConfiguration.getName(), name);

            if (customConfiguration.getName().compareTo(name) == 0) {

                final Integer value = Integer.valueOf(customConfiguration.getValue());
                log.debug("found  name {} value {}", name, value);

                return value;
            }

        }
        return 0;
    }

}
