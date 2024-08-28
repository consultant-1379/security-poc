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
package com.ericsson.oss.itpf.security.credmservice.util;

import java.lang.management.ManagementFactory;
import java.util.Set;

import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.impl.PKIMockManagement;

public class MBeanManager {

    private static final String JBOSS_SERVER_CONFIG_DIR = "jboss.as:path=jboss.server.config.dir";
    private static final String JBOSS_DEPLOYMENT = "jboss.as:deployment=*";
    private static final String JBOSS_SERVER_CONFIG_DIR_ATTRIBUTE = "path";
    private static final String PKI_MANAGER_EAR = "pki-manager-ear-";
    private static final String MOCK_PKI_MANAGER_EAR = "mock-pki-manager-ear-";

    private static final Logger log = LoggerFactory.getLogger(MBeanManager.class);

    private MBeanManager() {
    };

    public static String getJBossConfigPath() throws MalformedObjectNameException, AttributeNotFoundException, MBeanException, InstanceNotFoundException, ReflectionException {
        final ObjectName objectName = new ObjectName(JBOSS_SERVER_CONFIG_DIR);
        final MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
        final String outputPath = (String) platformMBeanServer.getAttribute(objectName, JBOSS_SERVER_CONFIG_DIR_ATTRIBUTE);
        return outputPath;
    }

    public static boolean getPKIManagerDeployed() throws MalformedObjectNameException, AttributeNotFoundException, InstanceNotFoundException, MBeanException, ReflectionException {
        String pkiEarLookup;
        if (!PKIMockManagement.useMockProfileManager() ) {
            log.info("Checking for PKI MANAGER deployed");
            pkiEarLookup = PKI_MANAGER_EAR;
        }
        else {
            log.info("Checking for MOCK PKI MANAGER deployed");
            pkiEarLookup = MOCK_PKI_MANAGER_EAR;
        }
        boolean ret = false;
        final MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
        final Set<ObjectName> names = platformMBeanServer.queryNames(new ObjectName(JBOSS_DEPLOYMENT), null);
        for (final ObjectName name : names) {
            final String deploymentName = platformMBeanServer.getAttribute(name, "name").toString();
            log.debug("------------______>  " + deploymentName);
            if (deploymentName.startsWith(pkiEarLookup)) {
                final String earstatus = (String) (platformMBeanServer.getAttribute(name, "status"));
                final Boolean earenabled = (Boolean) (platformMBeanServer.getAttribute(name, "enabled"));
                log.info(deploymentName + " has status : " + earstatus + "  enabled : " + earenabled);
                if ("OK".equals(earstatus) && earenabled ) {
                    ret = true;
                    log.info("PKI MANAGER deployed !!!");
                    break;
                }
            }
        }
        return ret;
    }


}
