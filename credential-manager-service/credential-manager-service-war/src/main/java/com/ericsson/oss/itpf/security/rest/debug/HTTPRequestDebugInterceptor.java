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
package com.ericsson.oss.itpf.security.rest.debug;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;

import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;
import org.slf4j.Logger;

//Uncomment this for test purpose (rest call)
//@Provider
//@ServerInterceptor
public class HTTPRequestDebugInterceptor implements PreProcessInterceptor {
    @Inject
    Logger logger;

    @Override
    public ServerResponse preProcess(final HttpRequest request, final ResourceMethod arg1) throws Failure, WebApplicationException {
        logger.info("interceptor called. Dumping request content...");
        final InputStream stream = request.getInputStream();

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        int len;
        try {
            while ((len = stream.read()) > -1) {
                baos.write(len);
            }
            baos.flush();
            stream.close();
        } catch (final IOException e) {
            e.printStackTrace();
        }
        final byte[] trimmedBuffer = baos.toByteArray();

        final InputStream is1 = new ByteArrayInputStream(trimmedBuffer);
        final String requestBody = new String(trimmedBuffer);
        logger.info(requestBody);
        request.setInputStream(is1);

        return null;
    }
}
