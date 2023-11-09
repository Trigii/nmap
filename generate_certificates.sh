#!/bin/bash

# Subject Name = organization
# Issuer Name = Common Name

# Function to generate a self-signed certificate
generate_self_signed_certificate() {
    echo "Generating self-signed certificate..."
    # Request Common Name (CN) from the user
    read -p "Enter Common Name (CN) for the self-signed certificate: " CN
    read -p "Enter Organization Name (O) for the self-signed certificate: " O
    openssl req -x509 -keyout demoCA/private/serverkey.pem -out demoCA/cert.pem -subj "/C=ES/ST=Madrid/L=Getafe/O=$O/OU=Cybersecurity/CN=$CN/emailAddress=example@alumnos.uc3m.es"
    echo "Self-signed certificate generated successfully."

    mv demoCA/cert.pem /etc/apache2/server.pem
    mv demoCA/private/serverkey.pem /etc/apache2/keyserver.pem

    # sudo service apache2 restart
}

generate_ca(){
    echo "Generating Certificate Authority (CA)..."
    # Request Common Name (CN) from the user
    read -p "Enter Common Name (CN) for the CA certificate: " CNca
    read -p "Enter Organization Name (O) for the CA certificate: " Oca
    openssl req -x509 -new -days 3650 -keyout demoCA/private/cakey.pem -out demoCA/cacert.pem -subj "/C=ES/ST=Madrid/L=Getafe/O=$Oca/OU=Cybersecurity/CN=$CNca/emailAddress=example@alumnos.uc3m.es"
    echo "CA generated successfully."

    mv demoCA/cacert.pem /etc/apache2/ca.pem
}

# Function to generate a CA and sign the user's certificate with it
generate_server_certificate_signed() {
    echo "Generating user's certificate..."
    # Request Common Name (CN) from the user
    read -p "Enter Common Name (CN) for the Server certificate: " CNserver
    read -p "Enter Organization Name (O) for the Server certificate: " Oserver
    openssl req -new -keyout demoCA/private/serverkey.pem -out demoCA/csr.pem -days 1 -subj "/C=ES/ST=Madrid/L=Getafe/O=$Oserver/OU=Cybersecurity/CN=$CNserver/emailAddress=example@alumnos.uc3m.es"
    openssl ca -in demoCA/csr.pem -out demoCA/cert.pem
    echo "User's certificate signed by the CA."

    mv demoCA/cert.pem /etc/apache2/server.pem
    mv demoCA/private/serverkey.pem /etc/apache2/keyserver.pem

    sudo /etc/init.d/apache2 restart
}

# Main script
# Verify if the directory exists
if [ -d "demoCA" ]; then
    rm -r "demoCA"
fi

# Create the directory again
echo "Creating the necessary folders and files..."
mkdir -p "demoCA/private"
mkdir -p "demoCA/newcerts"
touch demoCA/index.txt
echo 01 > demoCA/serial
echo 01 > demoCA/crlnumber

echo "Choose an option:"
echo "1. Generate a self-signed certificate"
echo "2. Generate Certificate Authority (CA)"
echo "3. Generate Servers Certificate and sign it by a CA"
read -p "Enter your choice: " choice

case $choice in
    1)
        generate_self_signed_certificate
        ;;
    2)
        generate_ca
        ;;
    3)
        generate_server_certificate_signed
        ;;
    *)
        echo "Invalid choice. Exiting."
        ;;
esac