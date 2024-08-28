/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.implementation;

import java.io.File;
import java.util.List;
import java.util.Properties;

import javax.xml.XMLConstants;
import javax.xml.bind.*;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerApplicationsImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ApplicationsType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ObjectFactory;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.*;

/**
 * 
 * @author ewagdeb
 * 
 */
public class AppClientXmlConfiguration implements
		ApplicationCertificateConfigInformation {
	/**
     * 
     */
        // TORF-562254 update log4j
        private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

	ApplicationsType applications;

	@SuppressWarnings("unused")
	private AppClientXmlConfiguration() {

	}

	@SuppressWarnings("unchecked")
	public AppClientXmlConfiguration(final File xmlPAth) {
		final Properties prop = PropertiesReader.getConfigProperties();

		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_READ_START_APPFILE),
				xmlPAth.getAbsolutePath());

		LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_READ_APPFILE),
				xmlPAth.toString());

		try {
			JAXBContext jaxbContext;
			jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
			Unmarshaller unmarshaller = null;

			unmarshaller = jaxbContext.createUnmarshaller();

			final SchemaFactory schemaFactory = SchemaFactory
					.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema;

			try {
				try {
					schema = schemaFactory.newSchema(FileSearch.getFile(prop
							.getProperty("path.xml.schema")));
				} catch (final Exception ex) {
					schema = schemaFactory
							.newSchema(AppClientXmlConfiguration.class
									.getClassLoader()
									.getResource(
											prop.getProperty("path.xml.schema")));
				}

			} catch (final SAXException e) {
				LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_XSD_FILE),
						prop.getProperty("path.xml.schema"));
				throw new CredentialManagerException(e.getCause());
			}
			unmarshaller.setSchema(schema);

			final JAXBElement<ApplicationsType> unmarshalledObject = (JAXBElement<ApplicationsType>) unmarshaller
					.unmarshal(xmlPAth);

			applications = unmarshalledObject.getValue();

		} catch (final JAXBException e) {
			LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_APPFILE),
					xmlPAth.getAbsolutePath());

			throw new CredentialManagerException(e.getCause());
		}
		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_READ_END_APPFILE),
				xmlPAth.getAbsolutePath());
	}

	/**
	 * @return the aptps
	 */
	public CredentialManagerApplications getAptps() {
		return new CredentialManagerApplicationsImpl(applications);
	}

	@Override
	public List<CredentialManagerApplication> getApplicationsInfo() {
		return getAptps().getApplications();
	}

}
