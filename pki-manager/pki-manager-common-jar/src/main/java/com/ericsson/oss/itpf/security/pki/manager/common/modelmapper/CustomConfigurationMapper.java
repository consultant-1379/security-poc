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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CustomConfigurationData;

public class CustomConfigurationMapper {

    @Inject
    private Logger logger;

    /**
     * Maps the CustomConfiguration API model to its corresponding JPA model
     *
     * @param apiModel
     *            CustomConfiguration Object which should be converted to JPA model CustomConfigurationData
     *
     * @return Returns the JPA model of the given API model
     *
     */
    public CustomConfigurationData fromAPIToModel(final CustomConfiguration apiModel) {

        final CustomConfiguration customConfiguration = apiModel;
        final CustomConfigurationData customConfigurationData = new CustomConfigurationData();

        customConfigurationData.setId(customConfiguration.getId());
        customConfigurationData.setName(customConfiguration.getName());
        customConfigurationData.setValue(customConfiguration.getValue());
        customConfigurationData.setNote(customConfiguration.getNote());
        customConfigurationData.setOwner(customConfiguration.getOwner());

        logger.debug("Mapped CustomConfigurationData CustomConfiguration is {}", customConfigurationData);
        return customConfigurationData;
    }

    /**
     * Maps the CustomConfigurationData JPA model to its corresponding API model
     *
     * @param dataModel
     *            CustomConfigurationData Object which should be converted to API model CustomConfiguration
     *
     * @return Returns the API model of the given JPA model
     *
     */
    public CustomConfiguration toAPIFromModel(final CustomConfigurationData dataModel) {

        final CustomConfigurationData entityCategoryData = dataModel;

        logger.info("Mapping CustomConfigurationData entity {} to Entity domain model.", entityCategoryData);

        final CustomConfiguration customCategory = new CustomConfiguration();
        final CustomConfigurationData customConfigurationData = dataModel;

        customCategory.setId(customConfigurationData.getId());
        customCategory.setName(customConfigurationData.getName());
        customCategory.setValue(customConfigurationData.getValue());
        customCategory.setNote(customConfigurationData.getNote());
        customCategory.setOwner(customConfigurationData.getOwner());

        logger.info("Mapped CustomConfiguration domain model is {}", customCategory);

        return customCategory;

    }
}
