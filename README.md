### LDAP Usermanagement

Ein Prototyp das als Weboberflächenschnittstelle zu einem Ldap-Server dient. die über Docker läuft.  
geschrieben mit Flask Webframework/Jinja.

Ausbaumöglichkeiten:

- CRUD einführen für Anfragen
- Security Aspekt absichern (Darf zurzeit nur in einem internen bzw. geschützten Netz laufen (Stichwort BasicAuth)
- generell Code säubern/effizienter machen

##### Step 1

Benötigten Anforderungen installieren

pip install -r requirements.txt

##### Step 2

In den Ordner "userinterface-project" gehen und virtualenv starten

source ./venv/bin/activate

dann in den ordner "usermanagement" gehen und

export FLASK_APP=start.py

eingeben.

danach "flask run" eingeben und es sollte funktionieren.

## Docker

Build

$ docker build . -t <name of image>

RUN

$ docker run -d --add-host ldap1.example.de:<ip> -p 5000:5000 --name=ldap_usermanagement registry.example.de/erika/ldap_usermanagement/master/ldap_usermanagement

## Deploy

Execute /root/deploy_usermanagement.sh on <ip>
