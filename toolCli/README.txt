====== Istruzioni per configurare il pkiadm tool ======

- in an empty directory of the director server, copy all contents of this toolCli directory

=== create python environment and activate it
- in the directory where toolCli contents are copied:

python3 -m venv .venv
. .venv/bin/activate
pip install -r ./requirements.txt

=== setup tunnel to SPS
- NOTE: if namespace is changed, align it in the script
- check if tunnel is up already

./spstunnel.sh status

- if tunnel is down, bring it up

./spstunnel start

=== now ./pkiadm.py should work.
- check if it is working with:

./pkiadm.py certmgmt CACert --listhierarchy --all


=== if you want stop the tunnel
- if you want to shut down the tunnel, retrieve the pid of the kubectl command with:

./spstunnel.sh status

- and then kill it.

