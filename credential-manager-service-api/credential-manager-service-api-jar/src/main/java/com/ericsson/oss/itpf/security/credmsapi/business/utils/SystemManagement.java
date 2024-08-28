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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Set;

import javax.management.*;
import javax.management.remote.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.SystemManagementException;

/**
 * @author egiator This uses jboss-as-client-all library to connect to the management port of a jboss and perform system operations on it.
 *
 */
public class SystemManagement {

    private static final Logger log = LogManager.getLogger(SystemManagement.class);
    private final static String HOSTNAME_DEFAULT = "localhost";
    private final static int PORT_DEFAULT = 9999; // management-native port

    private SystemManagement() {
    }

    /**
     * This utility stop and start a http/https jboss connector
     *
     * @param port
     *            The port used by the connector
     * @throws SystemManagementException
     */
    public static void restartHttpConnector(final int port) throws SystemManagementException {
        restartHttpConnector(port, HOSTNAME_DEFAULT, PORT_DEFAULT);
    }

    /**
     * This utility stop and start a http/https jboss connector
     *
     * @param port
     *            The port used by the connector
     * @param offset
     *            The offset value where all jboss ports are shifted
     * @throws SystemManagementException
     */
    public static void restartHttpConnector(final int port, final int offset) throws SystemManagementException {
        restartHttpConnector(port + offset, HOSTNAME_DEFAULT, PORT_DEFAULT + offset);
    }

    /**
     * This utility stop and start a http/https jboss connector
     *
     * @param port
     *            The port used by the connector
     * @param host
     *            The host where jboss is running
     * @param managementPort
     *            The Jboss management port
     * @throws SystemManagementException
     */
    public static void restartHttpConnector(final int port, final String host, final int managementPort) throws SystemManagementException {
        final String connectorPort = Integer.toString(port);
        final String urlString = System.getProperty("jmx.service.url", "service:jmx:remoting-jmx://" + host + ":" + managementPort);
        JMXServiceURL serviceURL;
        try {
            log.info("Trying to instantiate JMXServiceURl " + urlString);
            serviceURL = new JMXServiceURL(urlString);
        } catch (final MalformedURLException e1) {
            log.error("Unexpected. MalformedURLException received building JMXServiceURL from " + urlString);
            throw new SystemManagementException(e1.getCause());
        }
        try (JMXConnector jmxConnector = JMXConnectorFactory.connect(serviceURL, null)) {
            log.info("Trying to connect to MBean server");
            final MBeanServerConnection connection = jmxConnector.getMBeanServerConnection();

            final ObjectName obj = new ObjectName("jboss.web:type=Connector,address=*,port=*");
            final Set<ObjectName> objs = connection.queryNames(obj, null);

            for (final ObjectName o : objs) {
                if (connectorPort.equals(o.getKeyProperty("port"))) {
                    log.debug("Restarting connector " + o.getCanonicalName());
                    connection.invoke(o, "stop", null, null);
                    connection.invoke(o, "init", null, null);
                    connection.invoke(o, "start", null, null);
                }
            }
        } catch (InstanceNotFoundException | MBeanException | ReflectionException | IOException | MalformedObjectNameException e) { //NOSONAR
            final StringBuilder message = new StringBuilder("Exception caught restarting http connector\n");
            log.error("Exception Message : " + e.getMessage());
            throw new SystemManagementException(message.toString(), e.getCause()); 
        }
    }
}
