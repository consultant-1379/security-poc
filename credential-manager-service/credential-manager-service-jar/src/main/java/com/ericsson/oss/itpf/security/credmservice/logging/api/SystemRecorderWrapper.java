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
package com.ericsson.oss.itpf.security.credmservice.logging.api;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;

public interface SystemRecorderWrapper { 

    void recordCommand(String commandName, CommandPhase commandPhase, String source, String resource, String additionalInfo); 
   
    
    void recordError(String errorId, ErrorSeverity severity, String source, String resource, String additionalInformation);
    
    void recordEvent(String eventType,EventLevel eventLevel, String source,String resource,String additionalInformation);

}


