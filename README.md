# IP_extractor
IP EXTRACTOR FROM THE AUTH.LOG FILE EXTRACTS IPS THAT HAVE THE INVALID TAG AND SAVE THEM TO A BLACKLISTED.TXT FILE


#This is not needed in the project but I thought you should know if you want to check for listening ports on your machine use the commands below(any)
#sudo lsof -i -P -n | grep LISTEN
#sudo netstat -tulpn | grep LISTEN
#sudo ss -tulpn | grep LISTEN
#sudo lsof -i:22 ## see a specific port such as 22 ##
#sudo nmap -sTU -O IP-address-Here
