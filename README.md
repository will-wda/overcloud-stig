# Setup
Copy the templates folder into your current templates

You need to have the following packages installed for this to work properly
The image is expected to be build on a functional director. 

    sudo yum -y install libguestfs-xfs libguestfs-tools

Add to following to your deployment script

    -e /home/stack/templates/disable-stigged-services.yaml \
    -e /home/stack/templates/post-deploy-stig.yaml \

Make the script executable

    chmod +x stig-overcloud.sh

Execute the stig-overcloud script
Get a cup of coffee
Deploy your stigged image
Get another cup of coffee

### Prereqs
You will need your RHN username, password and a pool id to get software from for the overcloud image


