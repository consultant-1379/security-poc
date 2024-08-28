ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_NAME=eric-enm-credm-controller-base
ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
#ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_TAG=latest
ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_TAG=POC

FROM ${ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_REPO}/${ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_NAME}:${ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified

LABEL \
com.ericsson.product-number="CXC Placeholder" \
com.ericsson.product-revision=$RSTATE \
enm_iso_version=$ISO_VERSION \
org.label-schema.name="Credm Controller Image" \
org.label-schema.build-date=$BUILD_DATE \
org.label-schema.vcs-ref=$GIT_COMMIT \
org.label-schema.vendor="Ericsson" \
org.label-schema.version=$IMAGE_BUILD_VERSION \
org.label-schema.schema-version="1.0.0-rc1"

COPY ./image_content/ /credm/

RUN sudo pip3 install flask==2.0.1 gunicorn==20.1.0 --trusted-host proj-glims-pypi-local && \
    sudo pip3 install -r /credm/resources/requirements.txt

EXPOSE 5000 5001

# customize credentialmanagercli installation for cloud
# check if the strings to be replaced are present
RUN grep -q "OLD_FILES_MAINTAIN=45" /opt/ericsson/ERICcredentialmanagercli/conf/credentialmanagerconf.sh
RUN grep -q "purge_log_files() {" /opt/ericsson/ERICcredentialmanagercli/bin/credentialmanager.sh
RUN sed -i 's/OLD_FILES_MAINTAIN=45/OLD_FILES_MAINTAIN=10/g' /opt/ericsson/ERICcredentialmanagercli/conf/credentialmanagerconf.sh
RUN sed -i '/purge_log_files() {/ r /credm/resources/manualLogrotate.txt' /opt/ericsson/ERICcredentialmanagercli/bin/credentialmanager.sh
RUN rm /opt/ericsson/ERICcredentialmanagercli/conf/.stopCronVM

# keep the job running
#CMD exec /bin/bash -c "trap : TERM INT; sleep infinity & wait"
CMD "/credm/scripts/run.sh"

# gunicorn
#CMD ["gunicorn", "wsgi:application", "--chdir=/credm/src/", "--config=/credm/src/config.py"]

