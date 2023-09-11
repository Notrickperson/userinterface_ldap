FROM debian:buster-slim

RUN apt update && apt -y install python3 python3-pip python3-ldap
RUN pip3 install uwsgi flask flask-login flask-bootstrap flask-ldap3-login flask-user email-validator sshpubkeys
COPY usermanagement /srv/ 

WORKDIR /srv

CMD ["uwsgi", "--http", "0.0.0.0:5000", "--uid", "www-data", "--gid", "www-data", "--callable", "app", "--manage-script-name", "--mount", "/=start.py"]
