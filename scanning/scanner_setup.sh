#!/bin/bash

# Install klar

wget https://github.com/optiopay/klar/releases/download/v2.4.0/klar-2.4.0-linux-amd64
mv klar-2.4.0-linux-amd64 klar
sudo cp klar /usr/local/bin
sudo chmod +x /usr/local/bin/klar

# Install erlang

wget -O- https://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc | sudo apt-key add -
echo "deb https://packages.erlang-solutions.com/ubuntu bionic contrib" | sudo tee /etc/apt/sources.list.d/rabbitmq.list
sudo apt update
sudo apt -y install erlang

# Install RabbitMQ

wget -O- https://dl.bintray.com/rabbitmq/Keys/rabbitmq-release-signing-key.asc | sudo apt-key add -
wget -O- https://www.rabbitmq.com/rabbitmq-release-signing-key.asc | sudo apt-key add -
echo "deb https://dl.bintray.com/rabbitmq/debian $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/rabbitmq.list
sudo apt update
sudo apt -y install rabbitmq-server
