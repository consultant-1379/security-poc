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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.DynamicQueryBuilder;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

/**
 * This class used for build query dynamically based on ProfilesFilter and other utility methods
 *
 */
public class ProfileFilterDynamicQueryBuilder extends DynamicQueryBuilder {

    @Inject
    Logger logger;

    private static final String BASIC_QUERY = "select id, name, is_active, modified_date as TimeStamp, '";
    private static final String ALIAS_QUERY = "' \\:\\: text as type from ";
    private static final String UNION = " UNION ";
    private static final String AND = " AND ";
    private static final String WHERE = " WHERE ";
    /**
     * @param profilesFilter
     *            The {@link ProfilesFilter}
     * @param dynamicQuery
     *            dynamic Query String
     * @return returns parameters appended with given Criterias
     *
     */
    public Map<String, Object> build(final ProfilesFilter profilesFilter, final StringBuilder dynamicQuery) {
        return union(profilesFilter, dynamicQuery);
    }

    private Map<String, Object> union(final ProfilesFilter profilesFilter, final StringBuilder dynamicQuery) {
        final List<String> clauses = new ArrayList<String>();
        final StringBuilder whereQuery = new StringBuilder();

        final Map<String, Object> parameters = where(profilesFilter, whereQuery);

        if (ValidationUtils.isNullOrEmpty(profilesFilter.getType()) || profilesFilter.getType().contains(ProfileType.CERTIFICATE_PROFILE)) {
            clauses.add(BASIC_QUERY + ProfileType.CERTIFICATE_PROFILE.toString() + ALIAS_QUERY + "certificateprofile " + whereQuery);
        }
        if (ValidationUtils.isNullOrEmpty(profilesFilter.getType()) || profilesFilter.getType().contains(ProfileType.ENTITY_PROFILE)) {
            clauses.add(BASIC_QUERY + ProfileType.ENTITY_PROFILE.toString() + ALIAS_QUERY + "entityprofile " + whereQuery);
        }
        if (ValidationUtils.isNullOrEmpty(profilesFilter.getType()) || profilesFilter.getType().contains(ProfileType.TRUST_PROFILE)) {
            clauses.add(BASIC_QUERY + ProfileType.TRUST_PROFILE.toString() + ALIAS_QUERY + "trustprofile " + whereQuery);
        }
        dynamicQuery.append(addCriterias(clauses.toArray(new String[0]), UNION)).append(" order by TimeStamp DESC");

        logger.debug("Final query is {}", dynamicQuery);
        logger.debug("The parameters are {}", parameters);

        return parameters;
    }

    private Map<String, Object> where(final ProfilesFilter profilesFilter, final StringBuilder whereQuery) {
        final List<String> clauses = new ArrayList<String>();
        final Map<String, Object> parameters = new HashMap<String, Object>();
        if (!ValidationUtils.isNullOrEmpty(profilesFilter.getName())) {
            addCriteria("name", "LIKE", profilesFilter.getName(), "name", clauses, parameters);
        }
        if (profilesFilter.getStatus() != null) {
            clauses.add("is_active = :status_active or is_active != :status_inactive");
            parameters.put("status_active", profilesFilter.getStatus().isActive());
            parameters.put("status_inactive", profilesFilter.getStatus().isInactive());

        }

        if (!clauses.isEmpty()) {
            whereQuery.append(WHERE).append(addCriterias(clauses.toArray(new String[0]), AND));
        }
        return parameters;
    }

}
