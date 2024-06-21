#!/usr/bin/env bash

set -e

ENV_FILE="${ENV_FILE:-/.env}"
if [ ! -f $ENV_FILE ]; then
  echo "Error: $ENV_FILE does not exist. Quitting."
  exit 1
fi
source $ENV_FILE

if [[ -z "$KAFKA_0_FQDN" || -z $KAFKA_1_FQDN || -z $KAFKA_2_FQDN || -z $KAFKA_PASSWORD ]]; then
  echo "Error: unset variables in $ENV_FILE"
  echo "KAFKA_0_FQDN, KAFKA_1_FQDN, KAFKA_2_FQDN and KAFKA_PASSWORD must be set"
  echo "Quitting."
  exit 1
fi

if [ ! -x "$(command -v keytool)" ]; then
  echo 'Error: keytool is not installed. Quitting'
  exit 1
fi

if [ ! -w . ]; then
  echo 'Error: Unable to write to ${PWD}. Quitting'
  exit 1
fi

PASSWORD=$KAFKA_PASSWORD
CN="${CN:-kafka-admin}"
VALIDITY_IN_DAYS=3650
CA_WORKING_DIRECTORY="certificate-authority"
TRUSTSTORE_WORKING_DIRECTORY="truststore"
KEYSTORE_WORKING_DIRECTORY="keystore"
PEM_WORKING_DIRECTORY="pem"
CA_KEY_FILE="ca-key"
CA_CERT_FILE="ca-cert"
DEFAULT_TRUSTSTORE_FILE="kafka.truststore.jks"
KEYSTORE_SIGN_REQUEST="cert-file"
KEYSTORE_SIGN_REQUEST_SRL="ca-cert.srl"
KEYSTORE_SIGNED_CERT="cert-signed"


if [ -f "$CA_WORKING_DIRECTORY/$CA_KEY_FILE" ] && [ -f "$CA_WORKING_DIRECTORY/$CA_CERT_FILE" ]; then
  echo "Using existing $CA_WORKING_DIRECTORY/$CA_KEY_FILE and $CA_WORKING_DIRECTORY/$CA_CERT_FILE ..."
else
  rm -rf $CA_WORKING_DIRECTORY && mkdir $CA_WORKING_DIRECTORY
  echo
  echo "Generating $CA_WORKING_DIRECTORY/$CA_KEY_FILE and $CA_WORKING_DIRECTORY/$CA_CERT_FILE ..."
  echo
  openssl req -new -newkey rsa:4096 -days $VALIDITY_IN_DAYS -x509 -subj "/CN=$CN" \
    -keyout $CA_WORKING_DIRECTORY/$CA_KEY_FILE -out $CA_WORKING_DIRECTORY/$CA_CERT_FILE -nodes
fi

rm -rf $KEYSTORE_WORKING_DIRECTORY && mkdir $KEYSTORE_WORKING_DIRECTORY
for HOST in $KAFKA_0_FQDN $KAFKA_1_FQDN $KAFKA_2_FQDN client; do
  DNAME="CN=$HOST"
  EXT="SAN=dns:$HOST"
  KEY_STORE_FILE_NAME="${HOST}.keystore.jks"

  echo "Creating key pair and cert for $HOST"
  keytool -genkey -keystore $KEYSTORE_WORKING_DIRECTORY/"$KEY_STORE_FILE_NAME" \
    -alias localhost -validity $VALIDITY_IN_DAYS -keyalg RSA \
    -noprompt -dname $DNAME -keypass $PASSWORD -storepass $PASSWORD \
    -ext $EXT

  echo "Creating certificate signing request for $HOST"
  keytool -certreq -keystore $KEYSTORE_WORKING_DIRECTORY/"$KEY_STORE_FILE_NAME" \
    -alias localhost -file $KEYSTORE_SIGN_REQUEST -keypass $PASSWORD -storepass $PASSWORD \
    -ext $EXT

  echo "Signing $HOST keystore certificate."
  openssl x509 -req -CA $CA_WORKING_DIRECTORY/$CA_CERT_FILE \
    -CAkey $CA_WORKING_DIRECTORY/$CA_KEY_FILE \
    -in $KEYSTORE_SIGN_REQUEST -out $KEYSTORE_SIGNED_CERT \
    -days $VALIDITY_IN_DAYS -CAcreateserial -copy_extensions=copyall

  echo "Importing CA into ${HOST}'s keystore."
  keytool -keystore $KEYSTORE_WORKING_DIRECTORY/"$KEY_STORE_FILE_NAME" -alias CARoot \
    -import -file $CA_WORKING_DIRECTORY/$CA_CERT_FILE -keypass $PASSWORD -storepass $PASSWORD -noprompt

  echo "Importing signed certificate into ${HOST}'s keystore."
  keytool -keystore $KEYSTORE_WORKING_DIRECTORY/"$KEY_STORE_FILE_NAME" -alias localhost \
    -import -file $KEYSTORE_SIGNED_CERT -keypass $PASSWORD -storepass $PASSWORD

  echo "Complete keystore generation for $HOST"
  echo
  rm -f $CA_WORKING_DIRECTORY/$KEYSTORE_SIGN_REQUEST_SRL $KEYSTORE_SIGN_REQUEST $KEYSTORE_SIGNED_CERT
done

echo
echo "Generating truststore"
rm -rf $TRUSTSTORE_WORKING_DIRECTORY && mkdir $TRUSTSTORE_WORKING_DIRECTORY
keytool -keystore $TRUSTSTORE_WORKING_DIRECTORY/$DEFAULT_TRUSTSTORE_FILE \
  -alias CARoot -import -file $CA_WORKING_DIRECTORY/$CA_CERT_FILE \
  -noprompt -dname "CN=$CN" -keypass $PASSWORD -storepass $PASSWORD


echo
echo "Exporting client files to PEM format"

rm -rf $PEM_WORKING_DIRECTORY && mkdir $PEM_WORKING_DIRECTORY

keytool -exportcert -alias CARoot -keystore $KEYSTORE_WORKING_DIRECTORY/client.keystore.jks \
  -rfc -file $PEM_WORKING_DIRECTORY/ca-root.pem -storepass $PASSWORD

keytool -exportcert -alias localhost -keystore $KEYSTORE_WORKING_DIRECTORY/client.keystore.jks \
  -rfc -file $PEM_WORKING_DIRECTORY/client-certificate.pem -storepass $PASSWORD

keytool -importkeystore -srcalias localhost -srckeystore $KEYSTORE_WORKING_DIRECTORY/client.keystore.jks \
  -destkeystore cert_and_key.p12 -deststoretype PKCS12 -srcstorepass $PASSWORD -deststorepass $PASSWORD

openssl pkcs12 -in cert_and_key.p12 -nocerts -nodes -password pass:$PASSWORD \
  | awk '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/' > $PEM_WORKING_DIRECTORY/client-private-key.pem

rm -f cert_and_key.p12

echo
echo "Done!"
