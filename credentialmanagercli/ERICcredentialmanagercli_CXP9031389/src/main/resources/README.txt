Credential Manager is divided in 4 JARs:
1) credentialmanagercli-jar: Entry point for CLI. It uses credentialmanagercli-commands-jar to execute the commands.
2) credentialmanagercli-commands-jar: Has the logic to parse and validate commands. It uses credentialmanagercli-xmlbeans and credentialmanagercli-service-jar.
3) credentialmanagercli-service-jar: call the credential-manager-service-api to communicate with the Credential Manager inside the SPS (bastion host) to request certificates and trust chains.
4) credentialmanagercli-xmlbeans: Holds the objects used in commands-jar that map the XML into java Objects.

Dependencies: (Obs.: all properties and xsd, can be placed in rpm resources since it is the first place that credentialmanager will look, only after it will load from the classpath.)

credentialmanagercli-jar
|_	credentialmanagercli-commands-jar
	|_	resources
	|	|_config-cli.properties
	|	|_commands.properties
	|	|_log_error_messages.properties
	|	|_log_messages.properties
	|	|_log4j_error.properties
	|	|_log4j.properties
	|	
	|_	credentialmanagercli-service-jar
	|	|_	resources
	|		|_config-pki.properties
	|		|_jboss-ejb-client.properties
	|		|_ca_oss_enm_map.properties
	|		|_log_error_messages.properties
	|		|_log_messages.properties
	|		|_log4j_error.properties
	|		|_log4j.properties
	|
	|_	credentialmanagercli-xmlbeans
		|_	resources
			|_CertificateRequest.xsd
		
