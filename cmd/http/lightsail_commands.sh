Open a terminal window.

Enter the following command to download the lightsailctl plugin and copy it to the bin folder.


curl "https://s3.us-west-2.amazonaws.com/lightsailctl/latest/darwin-amd64/lightsailctl" -o "/usr/local/bin/lightsailctl"
Enter the following command to make the plugin executable.


chmod +x /usr/local/bin/lightsailctl
Enter the following command to clear extended attributes for the plugin.


xattr -c /usr/local/bin/lightsailctl


aws lightsail push-container-image --region us-west-2 --service-name link-session-service  --label session-server-label --image session-server:latest
aws lightsail create-container-service-deployment   --service-name link-session-service   --containers file://containers.json   --public-endpoint file://public-endpoint.json   --region us-west-2

aws lightsail get-container-services --service-name link-session-service --region us-west-2 --query 'containerServices[0].state'
#"DEPLOYING"

aws lightsail get-container-services --service-name link-session-service --region us-west-2 --query 'containerServices[0].currentDeployment.containers'
#{
#    "link-session-service": {
#        "image": ":link-session-service.session-server-img-3.5",
#        "command": [],
#        "environment": {
#            "BASIC_AUTH_PASSWORD": "XXXXXX",
#            "BASIC_AUTH_USER": "YYYYYY",
#            "CLOUDFLARE_BEARER_TOKEN": "ZZZZZZZZZZZ"
#        },
#        "ports": {
#            "8082": "HTTP"
#        }
#    }
#}

# grep logs
aws lightsail get-container-log   --service-name link-session-service   --container-name link-session-service   --region us-west-2   --output text | grep -i "error\|ERROR\|cloudflare\|turn"

#aws lightsail push-container-image --region us-west-2 --service-name link-session-service  --label session-server-img-2 --image session-server:latest
#7b1c94b69c6c: Layer already exists 
#Digest: sha256:8e1e85ec23151c7bb196024dbcb00c1b3dd36924d647cd7104c719cb58ed140d
#Image "session-server:latest" registered.
#Refer to this image as ":link-session-service.session-server-img-2.2" in deployments.