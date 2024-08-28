ARG ERIC_ENM_SLES_BASE_IMAGE_NAME=eric-enm-sles-base
ARG ERIC_ENM_SLES_BASE_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
ARG ERIC_ENM_SLES_BASE_IMAGE_TAG=1.34.0-19

FROM ${ERIC_ENM_SLES_BASE_IMAGE_REPO}/${ERIC_ENM_SLES_BASE_IMAGE_NAME}:${ERIC_ENM_SLES_BASE_IMAGE_TAG}

COPY ./image_content/ /tmp/
RUN mkdir /tmp/resources; mkdir /tmp/resources/test
#RUN mkdir /ericsson/credm; mkdir /ericsson/credm/district11; mkdir /ericsson/credm/district11/certs

#CMD /tmp/init.sh && tail -f /tmp/cron.log
# command to start script checking the certificates
CMD /tmp/startup.sh && /bin/bash
# command to start simple rest server
#CMD /tmp/startRest.sh && /bin/bash
