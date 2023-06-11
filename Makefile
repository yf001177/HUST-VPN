all: 
	gcc -o vpn_server my_vpn_server.c -lssl -lcrypto  -lcrypt -lpthread
	gcc -o vpn_client my_vpn_client.c -lssl -lcrypto

	sudo docker cp ./vpn_client HostU:/vpn_client
	sudo docker cp ./client.crt HostU:/cert/client.crt
	sudo docker cp ./client.key HostU:/cert/client.key
	sudo docker cp ./ca.crt HostU:/cert/ca.crt
	
	sudo docker cp ./vpn_client HostV:/vpn_client
	sudo docker cp ./client.crt HostV:/cert/client.crt
	sudo docker cp ./client.key HostV:/cert/client.key
	sudo docker cp ./ca.crt HostU:/cert/ca.crt

	sudo docker cp ./vpn_client HostW:/vpn_client
	sudo docker cp ./client.crt HostW:/cert/client.crt
	sudo docker cp ./client.key HostW:/cert/client.key
	sudo docker cp ./ca.crt HostW:/cert/ca.crt

clean: 
	rm -f vpn_server vpn_client

