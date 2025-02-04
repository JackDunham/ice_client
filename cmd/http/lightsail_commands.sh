Open a terminal window.

Enter the following command to download the lightsailctl plugin and copy it to the bin folder.


curl "https://s3.us-west-2.amazonaws.com/lightsailctl/latest/darwin-amd64/lightsailctl" -o "/usr/local/bin/lightsailctl"
Enter the following command to make the plugin executable.


chmod +x /usr/local/bin/lightsailctl
Enter the following command to clear extended attributes for the plugin.


xattr -c /usr/local/bin/lightsailctl


aws lightsail push-container-image --region us-west-2 --service-name session-server  --label session-server-label --image session-server:latest
aws lightsail create-container-service-deployment   --service-name session-server   --containers file://containers.json   --public-endpoint file://public-endpoint.json   --region us-west-2

