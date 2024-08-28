
echo " build [ all | credm | more | delete ] (opt)[repo name] (opt)[tag]"
echo "     all: default"
echo "     credm: only credm controller image"
echo "     more: only images for services"
echo "     delete: remove local versions"
echo ""
echo "     repo example: armdocker.rnd.ericsson.se/proj_oss_releases/enm"
echo "     default:armdocker.rnd.ericsson.se/proj-enm"
echo ""


build_all=true
build_credm=true
build_more=true
build_delete=false

if [ "$1" == "credm" ]
then
   build_all=false
   build_credm=true
   build_more=false
fi
if [ "$1" == "more" ]
then
   build_all=false
   build_credm=false
   build_more=true
fi
if [ "$1" == "delete" ]
then
   build_all=false
   build_credm=false
   build_more=false
   build_delete=true
fi

echo ""
echo "build_all: $build_all"
echo "build_credm: $build_credm"
echo "build_more: $build_more"
echo "build_delete: $build_delete"
echo ""

repo="armdocker.rnd.ericsson.se/proj-enm"
if [ -n "$2" ]; then
   repo=$2
   echo repo=$repo
fi


VERS="latest"
if [ ! -z "$3" ]; then
  VERS=$3
fi



echo ""
sleep 2

if [ "$build_delete" = true ]
then
  docker rmi ${repo}/eric-enm-credm-controller-base:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller-init:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller-job:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller-cron-job:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller:${VERS}
  docker rmi ${repo}/enm-wait-for-certificates-container:${VERS}
  docker rmi ${repo}/enm-certrequestjob-container:${VERS}
fi

if [ "$build_credm" = true ]
then
  docker rmi ${repo}/eric-enm-credm-controller:${VERS}
fi

if [ "$build_all" = true ]
then
  #remove old local versions
  docker rmi ${repo}/eric-enm-credm-controller-init:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller-job:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller-cron-job:${VERS}
  docker rmi ${repo}/eric-enm-credm-controller-base:${VERS}

  #build new images
  cd eric-enm-credm-controller-base
  docker build -f Dockerfile -t ${repo}/eric-enm-credm-controller-base:${VERS} . 
  cd ..
  cd eric-enm-credm-controller-init
  docker build -f Dockerfile -t ${repo}/eric-enm-credm-controller-init:${VERS} .
  cd ..
  cd eric-enm-credm-controller-job
  docker build -f Dockerfile -t ${repo}/eric-enm-credm-controller-job:${VERS} .
  cd ..
  cd eric-enm-credm-controller-cron-job
  docker build -f Dockerfile -t ${repo}/eric-enm-credm-controller-cron-job:${VERS} .
  cd ..
fi

if [ "$build_credm" = true ]
then
  docker build -f Dockerfile -t ${repo}/eric-enm-credm-controller:${VERS} .
fi

if [ "$build_more" = true ]
then
  cd waitForCertificatesImage
  docker rmi ${repo}/enm-wait-for-certificates-container:${VERS} 
  docker build -t ${repo}/enm-wait-for-certificates-container:${VERS} .
  cd ..
  cd certRequestImage
  docker rmi ${repo}/enm-certrequestjob-container:${VERS}
  docker build -t ${repo}/enm-certrequestjob-container:${VERS} .
fi

# to tag
# use docker tag 

# docker tag armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller:latest armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller:d11test
# docker tag armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-init:latest armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-init:d11test
# docker tag armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-job:latest armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-job:d11test
# docker tag armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-cron-job:latest armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-cron-job:d11test

# docker tag armdocker.rnd.ericsson.se/proj_oss_releases/enm/enm-wait-for-certificates-container:latest armdocker.rnd.ericsson.se/proj_oss_releases/enm/enm-wait-for-certificates-container:d11test
# docker tag armdocker.rnd.ericsson.se/proj_oss_releases/enm/enm-certrequestjob-container:latest armdocker.rnd.ericsson.se/proj_oss_releases/enm/enm-certrequestjob-container:d11test

# to push

#docker push armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-init:d11test
#docker push armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-job:d11test
#docker push armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-cron-job:d11test
#docker push armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller:d11test

#docker push armdocker.rnd.ericsson.se/proj_oss_releases/enm/enm-wait-for-certificates-container:d11test
#docker push armdocker.rnd.ericsson.se/proj_oss_releases/enm/enm-certrequestjob-container:d11test
#

# to delete tag

#docker rmi armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-init:d11test
#docker rmi armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-job:d11test
#docker rmi armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller-cron-job:d11test
#docker rmi armdocker.rnd.ericsson.se/proj_oss_releases/enm/eric-enm-credm-controller:d11test




