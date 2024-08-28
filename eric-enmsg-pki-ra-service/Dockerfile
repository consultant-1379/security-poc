ARG ERIC_ENM_SLES_EAP7_IMAGE_NAME=eric-enm-sles-eap7
ARG ERIC_ENM_SLES_EAP7_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
ARG ERIC_ENM_SLES_EAP7_IMAGE_TAG=1.29.0-6

FROM ${ERIC_ENM_SLES_EAP7_IMAGE_REPO}/${ERIC_ENM_SLES_EAP7_IMAGE_NAME}:${ERIC_ENM_SLES_EAP7_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified
ARG NEXUS_BASE_POC_URL=https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/service/local/artifact/maven/redirect?r=snapshots&g=com.ericsson.oss.itpf.poc.security

LABEL \
com.ericsson.product-number="CXC 174 1983" \
com.ericsson.product-revision=$RSTATE \
enm_iso_version=$ISO_VERSION \
org.label-schema.name="ENM PKIRAService Service Group" \
org.label-schema.build-date=$BUILD_DATE \
org.label-schema.vcs-ref=$GIT_COMMIT \
org.label-schema.vendor="Ericsson" \
org.label-schema.version=$IMAGE_BUILD_VERSION \
org.label-schema.schema-version="1.0.0-rc1"

RUN rpm -e --nodeps ERICcredentialmanagercli_CXP9031389 || echo "No ERICcredentialmanagercli_CXP9031389 installed"


RUN zypper install -y ERICpostgresqljdbc_CXP9031176 \
    ERICserviceframework4_CXP9037454 \
    ERICserviceframeworkmodule4_CXP9037453 \
    ERICmodelserviceapi_CXP9030594 \
    ERICpib2_CXP9037459 \
    ERICmodelservice_CXP9030595 \
    # ERICpkirascep_CXP9031951 \
    # ERICpkiracmp_CXP9031945 \
    # ERICpkiratdps_CXP9032423 \
    # ERICpkicdps_CXP9032210 \
    # ERICpkiservicedb_CXP9031995 \
    sles_base_os_repo:postgresql13 \
    ERICvaultloginmodule_CXP9036201 \
    ERICpostgresutils_CXP9038493 \
    wget && \
    zypper download ERICenmsgpkiraservice_CXP9031961 && \
    rpm -ivh /var/cache/zypp/packages/enm_iso_repo/ERICenmsgpkiraservice_CXP9031961*.rpm --nodeps --noscripts && \
    zypper clean -a && \
    rm -f /ericsson/3pp/jboss/bin/pre-start/copy_cache_replication_config_xml_files.sh && \
    rm -f /ericsson/3pp/jboss/bin/pre-start/oomKillerTuning.sh

RUN wget -q -O /tmp/ERICpkiracmp_CXP9031945.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkiracmp_CXP9031945&v=1.0.2-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkirascep_CXP9031951.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkirascep_CXP9031951&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkiratdps_CXP9032423.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkiratdps_CXP9032423&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkicdps_CXP9032210.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkicdps_CXP9032210&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkiservicedb_CXP9031995.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkiservicedb_CXP9031995&v=1.0.1-SNAPSHOT&p=rpm"

RUN rpm -ivh /tmp/ERICpkiracmp_CXP9031945.rpm && \
    rpm -ivh /tmp/ERICpkirascep_CXP9031951.rpm && \
    rpm -ivh /tmp/ERICpkiratdps_CXP9032423.rpm && \
    rpm -ivh /tmp/ERICpkicdps_CXP9032210.rpm && \
    rpm -ivh /tmp/ERICpkiservicedb_CXP9031995.rpm

RUN mkdir -p /opt/rh/postgresql92/root/usr/
RUN ln -s /usr/lib/postgresql13/bin /opt/rh/postgresql92/root/usr/
RUN mkdir -p /opt/rh/postgresql/
RUN ln -s /usr/lib/postgresql13/bin /opt/rh/postgresql/
RUN sed -i 's/-aes-128-cbc -kfile/-aes-128-cbc -md md5 -kfile/g'  /ericsson/enm/pg_utils/lib/pg_password_library.sh
RUN sed -i 's/-aes-128-cbc -k/-aes-128-cbc -md md5 -k/g' /ericsson/enm/pg_utils/lib/pg_password_library.sh

COPY image_content/dump_date.sh /var/tmp/dump_date.sh
RUN /bin/chmod 755 /var/tmp/dump_date.sh
COPY --chown=jboss_user:jboss image_content/bcpkix-jdk15on-1.52.jar /opt/ericsson/jboss/modules/org/bouncycastle/main/
COPY --chown=jboss_user:jboss image_content/bcprov-jdk15on-1.52.jar /opt/ericsson/jboss/modules/org/bouncycastle/main/
COPY --chown=jboss_user:jboss image_content/pkira_serv.config /var/tmp/

COPY image_content/createCertificatesLinks.sh /ericsson/3pp/jboss/bin/pre-start/createCertificatesLinks.sh
# TORF-537452 : TEMP to remove when script that restarts mediation PODS in CIS-149159 will be fixed
COPY image_content/credentialmanagercliRestartVM.sh /usr/lib/ocf/resource.d/credentialmanagercliRestartVM.sh
RUN mkdir -p -m 777 /opt/ericsson/ERICcredentialmanagercli && chmod 755 /usr/lib/ocf/resource.d/credentialmanagercliRestartVM.sh

RUN /bin/chown jboss_user:jboss /ericsson/3pp/jboss/bin/pre-start/createCertificatesLinks.sh
RUN /bin/chmod 755 /ericsson/3pp/jboss/bin/pre-start/createCertificatesLinks.sh

COPY image_content/updateCertificatesLinks.sh /usr/lib/ocf/resource.d/updateCertificatesLinks.sh
RUN /bin/chmod 755 /usr/lib/ocf/resource.d/updateCertificatesLinks.sh

RUN /bin/mkdir -p /ericsson/credm/data/certs && \
    /bin/chown -R jboss_user:jboss /ericsson/credm/data/certs && \
    /bin/chmod -R 755 /ericsson/credm/data/certs 

RUN chmod 755 /var/tmp/dump_date.sh

ENV ENM_JBOSS_SDK_CLUSTER_ID="pkiraserv" \
    ENM_JBOSS_BIND_ADDRESS="0.0.0.0" \
    JBOSS_CONF="/ericsson/3pp/jboss/app-server.conf"

#Technical Debt - This depends on a study to be done so we can remove cmserv_config.sh.
RUN sed -i "12 a bash /var/tmp/pkira_serv.config" /ericsson/3pp/jboss/entry_point.sh

EXPOSE 3528 4447 8009 8080 8090 8091 8092 8093 9990 9999 12987 39303 56403 56409 56415 56450 56453 56456
