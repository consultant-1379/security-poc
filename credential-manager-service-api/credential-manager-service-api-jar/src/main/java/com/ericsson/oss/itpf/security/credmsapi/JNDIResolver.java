package com.ericsson.oss.itpf.security.credmsapi;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.naming.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;

/**
 * resolve the JNDI name using the names specified in the properties file.
 */
public class JNDIResolver {

    public static final String CREDENTIAL_MANAGER_PROPERTIES = "credentialmanager.properties";
    public static final String CREDENTIAL_MANAGER_SERVICE_NAME = "credential.manager.service.name";
    public static final String CREDENTIAL_MANAGER_SERVICE_INTERFACE_VERSION = "credential.manager.service.interface.version";
    

    private static final Logger LOG = LogManager.getLogger(JNDIResolver.class);
    private final Properties properties;

    public JNDIResolver() {

        final InputStream resource2 = JNDIResolver.class.getResourceAsStream(CREDENTIAL_MANAGER_PROPERTIES);

        //String path = null;

        try {

            this.properties = new Properties();
            this.properties.load(resource2);

        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_LOAD_CMPROPERTIES);
            throw new IllegalStateException(e);
        }
    }

    private Context initJNDIContext() throws NamingException {
        final Properties jndiProperties = new Properties();
        jndiProperties.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
        final Context context = new InitialContext(jndiProperties);
        return context;
    }

    public CredMService resolveCredMService() {
        String lookupName = "";
        Context context = null;
        try {
            context = this.initJNDIContext();
            LOG.info("JNDI initial context has been initialized.");
            lookupName = (String) this.properties.get(CREDENTIAL_MANAGER_SERVICE_NAME);
            LOG.info("looking up credential manager service given the name: " + lookupName);
            final CredMService service = (CredMService) context.lookup(lookupName);
            //            if (!CredMService.CMSERVICE_VERSION.equals(service.getVersion())) {
            //                LOG.debug(ErrorMsg.API_ERROR_SERVICE_JNDI_RESOLVE_VERSION, lookupName, CredMService.CMSERVICE_VERSION);
            //                //throw new IllegalStateException("could not resolve the JNDI name for credential manager service given lookup name:" + lookupName);
            //            }
            return service;
        } catch (final NamingException e) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_JNDI_RESOLVE, lookupName);
            throw new IllegalStateException("could not resolve the JNDI name for credential manager service given lookup name:" + lookupName, e);

        } finally {
            // close the context to allow JVM to close the JNDI connections
            if (context != null) {
                try {
                    context.close();
                } catch (final NamingException e) {
                    // TODO Auto-generated catch block
                    //e.printStackTrace();
                }
            }
        }
    }
    
    public String getInterfaceVersion() {
        final String version = (String) this.properties.get(CREDENTIAL_MANAGER_SERVICE_INTERFACE_VERSION);
        LOG.info("Read credential.manager.service.interface.version = " + version);
        return version;
    }

}
