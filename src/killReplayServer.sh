sudo kill `ps -ef |grep 'replay_server.py' |grep -v grep |awk '{print $2}'`
