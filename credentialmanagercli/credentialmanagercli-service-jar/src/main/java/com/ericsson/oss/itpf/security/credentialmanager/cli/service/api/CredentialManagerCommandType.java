/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.util.ArrayList;
import java.util.List;

public class CredentialManagerCommandType {

    protected List<String> pathname;
    protected List<String> parameterName;
    protected List<String> parameterValue;
    
    /**
     * 
     */
    public CredentialManagerCommandType() {
        super();
        this.pathname = new ArrayList<String>();
        this.parameterName = new ArrayList<String>();
        this.parameterValue = new ArrayList<String>();
    }
    
    /**
     * @return the pathname
     */
    public List<String> getPathname() {
        return this.pathname;
    }
    
    /**
     * @param pathname the pathname to set
     */
    public void setPathname(final List<String> pathname) {
        this.pathname = pathname;
    }
    
    /**
     * 
     * @param pathname
     */
    public void addPathname(final String pathname) {
        this.pathname.add(pathname);
    }
    
    /**
     * @return the parameterName
     */
    public List<String> getParameterName() {
        return this.parameterName;
    }
    
    /**
     * @param parameterName the parameterName to set
     */
    public void setParameterName(final List<String> parameterName) {
        this.parameterName = parameterName;
    }
    
    /**
     * 
     * @param pathname
     */
    public void addParameterName(final String parameterName) {
        this.parameterName.add(parameterName);
    }
    
    /**
     * @return the parameterValue
     */
    public List<String> getParameterValue() {
        return this.parameterValue;
    }
    
    /**
     * @param parameterValue the parameterValue to set
     */
    public void setParameterValue(final List<String> parameterValue) {
        this.parameterValue = parameterValue;
    }
    
    /**
     * 
     * @param pathname
     */
    public void addParameterValue(final String parameterValue) {
        this.parameterValue.add(parameterValue);
    }
    

} // end of CredentialManagerCommandType

