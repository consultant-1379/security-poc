/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.cli.manager;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import javax.inject.Inject;

import com.ericsson.oss.services.cm.admin.domain.SnmpData;
import com.ericsson.oss.services.cm.admin.validation.ParametersValidationFactory;
import com.ericsson.oss.services.cm.admin.validation.ValidationResult;

/**
 * This class manage the parameter.
 */
public class ParameterManager {
    @Inject
    private ParametersValidationFactory parametersValidationFactory;

    private static final HashMap<String, Class> PARM_STORAGE_TYPE = new HashMap<>();
    private static final HashMap<String, Class> PARM_DATA_TYPE = new HashMap<>();
    private static final HashMap<String, Boolean> PARM_CONTAIN_PASSWORD = new HashMap<>();

    static {
        addSupportedParm("NODE_SNMP_SECURITY", String[].class, SnmpData.class, true);
        addSupportedParm("NODE_SNMP_INIT_SECURITY", String[].class, SnmpData.class, true);
        addSupportedParm("AP_SNMP_AUDIT_TIME", String.class, String.class, false);
    }

    private static void addSupportedParm(final String parmName, final Class storageType, final Class dataType, final Boolean passwordParameter) {
        PARM_STORAGE_TYPE.put(parmName, storageType);
        PARM_DATA_TYPE.put(parmName, dataType);
        PARM_CONTAIN_PASSWORD.put(parmName, passwordParameter);
    }

    /**
     * Check if the given parameter name is supported for view.
     *
     * @param parmName
     *            the parameter name
     * @return boolean for if it's supported.
     */
    public boolean isSupportedParm(final String parmName) {
        return (PARM_STORAGE_TYPE.get(parmName) != null);
    }

    /**
     * Get the storage type for the specific parameter name.
     *
     * @param parmName
     *            the parameter name
     * @return the class of storage type.
     */
    public Class getStorageType(final String parmName) {
        return PARM_STORAGE_TYPE.get(parmName);
    }

    /**
     * Check if the given parm contains password.
     *
     * @param parmName
     *            the parameter name
     * @return Boolean for whether the parm contains password.
     */
    public boolean isPasswordParameter(final String parmName) {
        Boolean isPasswordField = PARM_CONTAIN_PASSWORD.get(parmName);
        return isPasswordField != null && isPasswordField;
    }

    /**
     * Get the data type for the specific parameter name.
     *
     * @param parmName
     *            the parameter name
     * @return the class of data type.
     */
    public Class getDataType(final String parmName) {
        return PARM_DATA_TYPE.get(parmName);
    }

    /**
     * Get the All Supported Parm List
     * @return the List of Supported Parm.
     */
    public List<String> getSupportedParmList(){
        List<String> parmList = PARM_STORAGE_TYPE.keySet().stream().collect(Collectors.toList());
        parmList.sort(String.CASE_INSENSITIVE_ORDER);
        return parmList;
    }

    public ValidationResult paramValidation(final String parmName, final String parmValue) {
        switch (parmName) {
            case "NODE_SNMP_SECURITY":
            case "NODE_SNMP_INIT_SECURITY":
                return parametersValidationFactory.validateSnmpData(parmValue);
            case "AP_SNMP_AUDIT_TIME":
                return parametersValidationFactory.validateAuditTime(parmValue);
            default:
                return parametersValidationFactory.validateData(parmValue);
        }
    }
}
