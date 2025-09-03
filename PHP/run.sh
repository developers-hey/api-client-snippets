#!/bin/bash

# Script para ejecutar el cliente PHP con configuración OpenSSL adecuada

echo "Ejecutando cliente PHP API..."
OPENSSL_CONF=/tmp/openssl_legacy.cnf php APIClient/src/main/php/Client.php
