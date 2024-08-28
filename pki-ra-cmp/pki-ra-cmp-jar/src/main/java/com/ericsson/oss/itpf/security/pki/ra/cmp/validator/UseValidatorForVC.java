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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator;

import java.lang.annotation.*;

/**
 * This qualifier is used for seggregating request validators for IAK and VC requests. For eg:DigitalSignature validation is for VC only, so that will be a part of UseValidatorForVC.Ideally all
 * requestHandlers will use <code>UseValidatorForVC</code>
 * <p>
 * Example:
 * </p>
 * 
 * <code><pre>
 *      {@literal @}RequestType(ModelConstant.TYPE_INIT_REQ )
 *      {@literal @}UseValidatorForVC(DigitalSignatureValidator.class)
 *      public class InitializationRequestHandler implements RequestHandler {
 * 
 *          public String handleMessage(RequestMessage pKIRequestmessage) {
 *                // Handler implementation...
 *          }
 *      }
 * </pre></code>
 * 
 * @author tcsdemi
 *
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface UseValidatorForVC {

    Class<? extends RequestValidator>[] value();

}
