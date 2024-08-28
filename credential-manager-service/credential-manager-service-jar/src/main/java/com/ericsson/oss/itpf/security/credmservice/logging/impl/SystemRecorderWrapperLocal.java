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

package com.ericsson.oss.itpf.security.credmservice.logging.impl;


import javax.enterprise.context.Dependent;
import javax.inject.Inject;



import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.credmservice.impl.RBACManagement;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;


@Dependent
public class SystemRecorderWrapperLocal implements SystemRecorderWrapper  {


    private static final String SERVICE_NAME= "Credential Manager Service: ";
   
   
    @Inject
    private  SystemRecorder systemRecorder;
    
    @Inject
    private ContextService ctxService;

    /**
     * Method to record a command
     *
     * @param commandName
     *            - contains info on the command source and operation
     * @param commandPhase
     *            - contains info on the command phase
     * @param source
     *            - contains source of the command
     * @param resource
     *            - String: the resource that the command is working on, good example is a subscription poid or fdn.
     * @param additionalInfo
     *            - additionalInfo - text with additional information.
     *            
     */   
   
    @Override
    public void recordCommand(String commandName, CommandPhase commandPhase, String source, String resource, String additionalInfo) {
      RBACManagement.injectUserName(ctxService);
        systemRecorder.recordCommand(commandName, commandPhase, SERVICE_NAME+source, resource,additionalInfo);
        
    }

    /**
     * Method to record an error
     *
     * @param errorId
     *            -  contains info the type of the error recorded
     * @param severity
     *            - contains info on severity Level, must be not be null
     * @param source
     *            - contains source of the command
     * @param resource
     *            - String: the resource that the command is working on, good example is a subscription poid or fdn.
   * @param additionalInfo
     *            - additionalInfo - text with additional information.
     *            
     */   
    
    @Override
    public void recordError(String errorId, ErrorSeverity severity, String source, String resource, String additionalInformation) {
        RBACManagement.injectUserName(ctxService);
        systemRecorder.recordError(errorId, severity, SERVICE_NAME+source, resource,additionalInformation);
        
    }
    
    /**
     * Method to record an event
     *
     * @param eventType
     *            -  contains info the type of the event
     * @param eventLevel
     *            - contains info on  Level, must be not be null
     * @param source
     *            - contains source of the command
     * @param resource
     *            - String: the resource that the command is working on, good example is a subscription poid or fdn.
   * @param additionalInfo
     *            - additionalInfo - text with additional information.
     *            
     */   

    @Override
    public void recordEvent(String eventType,EventLevel eventLevel, String source,String resource,String additionalInformation) {
        RBACManagement.injectUserName(ctxService);
        systemRecorder.recordEvent(eventType, eventLevel, SERVICE_NAME+source, resource,additionalInformation);
    }


  


}
