package com.ericsson.itpf.security.pki.cmhandler.handler.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to associate one or more CommandValidator to a CommandHandler implementation
 *
 * Created by emaynes on 01/05/2014.
 *
 * @see com.ericsson.PKIWebCLIValidator.security.CredMWebCLIValidator.handler.validation.CommandValidator
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface UseValidator {
    Class<? extends PKIWebCLIValidator>[] value();
}
