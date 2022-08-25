Open a connection and run below command:
python client.py -e end_servers.txt. -r relay_nodes.txt

Start as many connections as the numbers of the relays, and run the below command at each server:
python relay_node.py
