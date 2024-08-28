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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;

/**
 * This class is an interface which return responseBuilders crresponding to ResquestType. <br>
 * Method:<br>
 * <code>ResponseBuilder getResponseBuilder(RequestMessage pKIRequestMessage)</code><br>
 * ResponseBuidlerFactory implements this class.
 * 
 * @author tcsdemi
 *
 */
public interface ResponseBuilderFactory {
    /**
     * This is a factory class which gives corresponding responseBuilder based on requestMessage
     * 
     * @param pKIRequestMessage
     * @return instance of ResponseBuilder implementors
     */
    ResponseBuilder getResponseBuilder(RequestMessage pKIRequestMessage);

}
