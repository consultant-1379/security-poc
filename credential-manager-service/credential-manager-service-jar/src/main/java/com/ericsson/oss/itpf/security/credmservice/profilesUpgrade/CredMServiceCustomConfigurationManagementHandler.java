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

import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.impl.PKIMockManagement;
import com.ericsson.oss.itpf.security.credmservice.impl.RBACManagement;
import com.ericsson.oss.itpf.security.credmservice.util.FileUtils;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;
import com.ericsson.oss.services.security.pkimock.api.MockCustomConfigurationManagementService;

@Stateless
public class CredMServiceCustomConfigurationManagementHandler {
    @Inject
    private ContextService ctxService;

    @EServiceRef
    CustomConfigurationManagementService pkiCustomConfigurationManagementService;

    @EServiceRef
    MockCustomConfigurationManagementService mockCustomConfigurationManagementService;

    private static final String CVN_FILE = PropertiesReader.getConfigProperties().getProperty("path.cvn");

    private static final String CVN_OWNER = "credm";

    private static final Logger log = LoggerFactory.getLogger(CredMServiceCustomConfigurationManagementHandler.class);
    CustomConfigurations credMCustomConfigurations = null;

    private static String[] cvnParameters = null;

    /**
     * @return CustomConfigurations read from properties file
     */

    CustomConfigurations getCredMServiceCustomConfigurations() {

        final List<CustomConfiguration> customConfigurationsList = new ArrayList<CustomConfiguration>();

        if (FileUtils.isExist(CVN_FILE)) {

            final String cvnString = PropertiesReader.getProperties(CVN_FILE).getProperty("properties");
            cvnParameters = cvnString.split(":");
            if (cvnParameters.length == 0) {
                log.error("cvnParameters fields not correct " + cvnString);
                return null;
            }
            log.debug("cvn properties is: {} read from property files are: {}", cvnParameters.length, cvnParameters);

            credMCustomConfigurations = new CustomConfigurations();

            for (int i = 0; i < cvnParameters.length; i++) {
                log.debug("Looking {}", cvnParameters[i]);
                customConfigurationsList.add(readCustomConfigurationParameters(cvnParameters[i]));
                log.info("credm {} custom configuration is {}", cvnParameters[i], customConfigurationsList.get(i));
            }

            return this.prepareCustomConfigurationsObject(customConfigurationsList);
        }
        // in case of error reading configuration file 
        return null;
    }

    /**
     * @param customConfiguration
     * @return
     */
    private CustomConfigurations prepareCustomConfigurationsObject(final List<CustomConfiguration> customConfiguration) {

        final CustomConfigurations customConfigurations = new CustomConfigurations();
        log.debug("Filling prepareCustomConfigurationsObject with:" + customConfiguration.toString());
        customConfigurations.setCustomConfigurations(customConfiguration);
        return customConfigurations;
    }

    /**
     * @param parameter
     */

    private CustomConfiguration readCustomConfigurationParameters(final String parameter) {
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setName(parameter);

        customConfiguration.setValue(PropertiesReader.getPropertiesFromFileSystem(CVN_FILE).getProperty(parameter, "0"));

        customConfiguration.setNote(PropertiesReader.getPropertiesFromFileSystem(CVN_FILE).getProperty("note", "no-reason"));
        customConfiguration.setOwner(PropertiesReader.getPropertiesFromFileSystem(CVN_FILE).getProperty("owner", CVN_OWNER));

        return customConfiguration;

    }

    /**
     * @param name
     */

    private CustomConfiguration prepareCustomConfigurationObject(final String name) {
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setName(name);
        customConfiguration.setOwner(CVN_OWNER);
        return customConfiguration;
    }

    /**
     * @return
     */

    public CustomConfigurations getPkiCustomConfigurations()
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {

        final CustomConfigurationManagementService pkiHierarchyConfigurationVersion = this.getPkiCustomConfigurationManagementService();

        CustomConfigurations pkiCustomConfigurationParameters = null;

        if (checkPkiCustomConfigurationsPresence()) {

            final List<CustomConfiguration> customConfiguration = fillCustomConfigurationList();

            final CustomConfigurations customConfigurations = prepareCustomConfigurationsObject(customConfiguration);
            log.info("Asked to PKI " + customConfigurations.toString());

            pkiCustomConfigurationParameters = pkiHierarchyConfigurationVersion.getCustomConfigurations(customConfigurations);

            log.info("Received from PKI " + pkiCustomConfigurationParameters.toString());
        }
        return pkiCustomConfigurationParameters;

    }

    /**
     * @return
     */

    private List<CustomConfiguration> fillCustomConfigurationList() {
        final List<CustomConfiguration> customConfiguration = new ArrayList<CustomConfiguration>();

        for (int i = 0; i < cvnParameters.length; i++) {
            customConfiguration.add(prepareCustomConfigurationObject(cvnParameters[i]));
        }
        return customConfiguration;
    }

    /**
     * @return
     */

    private boolean checkPkiCustomConfigurationsPresence() throws CustomConfigurationInvalidException, CustomConfigurationServiceException {

        final CustomConfigurationManagementService pkiHierarchyConfigurationVersion = this.getPkiCustomConfigurationManagementService();

        final List<CustomConfiguration> customConfiguration = fillCustomConfigurationList();

        boolean presenceFlag = false;
        for (int i = 0; i < cvnParameters.length; i++) {
            if (pkiHierarchyConfigurationVersion.isPresentCustomConfiguration(customConfiguration.get(i))) {
                presenceFlag = true;
                log.info("found on PKI " + customConfiguration.get(i).getName());
            } else {
                log.info("NOT found on PKI " + customConfiguration.get(i).getName());
            }
        }
        return presenceFlag;

    }

    /**
     * @param credMCustomConfigurations
     * @throws CustomConfigurationAlreadyExistsException
     */

    public void setPkiCustomConfigurationsUpdate(final CustomConfigurations credMCustomConfigurations)
            throws CustomConfigurationInvalidException, CustomConfigurationServiceException, CustomConfigurationAlreadyExistsException {

        final CustomConfigurationManagementService pkiHierarchyConfigurationVersion = this.getPkiCustomConfigurationManagementService();

        if (checkPkiCustomConfigurationsPresence()) {
            log.info("Updating customConfigurationParameters {}", credMCustomConfigurations);

            pkiHierarchyConfigurationVersion.updateCustomConfigurations(credMCustomConfigurations);
        } else {
            log.info("Creating customConfigurationParameters {}", credMCustomConfigurations);

            pkiHierarchyConfigurationVersion.createCustomConfigurations(credMCustomConfigurations);
        }
    }

    /**
     * @return CustomConfigurationManagementService
     */

    private CustomConfigurationManagementService getPkiCustomConfigurationManagementService() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockCvn()) {
            log.info("using mock customConfiguration service");
            return this.mockCustomConfigurationManagementService;
        } else {
            log.info("using pki customConfiguration service");
            return this.pkiCustomConfigurationManagementService;
        }
    }
}
