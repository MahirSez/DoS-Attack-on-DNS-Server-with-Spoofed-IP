FILE_NAME=rawudp
gcc $FILE_NAME.c -o $FILE_NAME
sudo ./rawudp 1.2.3.4 10 192.168.0.104 30
# ./dnsreq "www.youtube.com"