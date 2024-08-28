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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler;

import java.util.List;
import java.util.Map;

/**
 * This class used for build query dynamically and other utility methods
 *
 */
public abstract class DynamicQueryBuilder {

    /**
     * Used build criteria for column
     * 
     * @param columnName
     *            Column name in JPA Entity
     * @param operator
     *            The SQL operators
     * @param columnValue
     *            Column value for corresponding column name
     * @param columnAlias
     *            alias name for each column name
     * @param clauses
     * 
     * @param parameters
     */
    public void addCriteria(final String columnName, final String operator, final Object columnValue, final String columnAlias, final List<String> clauses, final Map<String, Object> parameters) {
        clauses.add(columnName + " " + operator + " :" + columnAlias);
        parameters.put(columnAlias, columnValue);
    }

    /**
     * Build Order by clause
     * 
     * @param orderByColumn
     *            Column name
     * @param orderby
     *            order by ASC\DESC
     * @return returns SQL string with order by clause
     */
    public String orderBy(final String orderByColumn, final String orderby) {
        final String orderByClause = " ORDER BY " + orderByColumn + " " + orderby;
        return orderByClause;
    }

    /**
     * Convert Object Array into SQL IN values separated by comma(,)
     * 
     * @param values
     *            any wrapper class Object array
     * @return SQL IN values separated by comma(,)
     */
    public String inOperatorValues(final Object[] values) {
        StringBuilder bulidSQLINValues = new StringBuilder();
        if (values == null || values.length == 0) {
            return bulidSQLINValues.toString();
        }
        bulidSQLINValues.append("(");
        for (int i = 0; i < values.length; i++) {
            bulidSQLINValues.append(values[i]).append(",");
        }
        String bulidSQLINValuesSubString = bulidSQLINValues.substring(0, bulidSQLINValues.length() - 1);
        bulidSQLINValuesSubString += ")";
        return bulidSQLINValuesSubString;
    }

    /**
     * Constructs SQL WHERE Clause AND operation by each clause
     * 
     * @param clauses
     *            clauses
     * @param separator
     *            delimiter
     * @return SQL WHERE Clause AND operation by each clause
     */
    public String addCriterias(final String[] clauses, String separator) {

        final String EMPTY = "";
        if (clauses == null) {
            return null;
        }
        if (separator == null) {
            separator = EMPTY;
        }
        final StringBuilder buf = new StringBuilder();
        for (int i = 0; i < clauses.length; i++) {
            if (i > 0) {
                buf.append(separator);
            }
            if (clauses[i] != null) {
                buf.append(clauses[i]);
            }
        }
        return buf.toString();
    }

}
