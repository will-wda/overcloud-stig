# Setup
Copy the templates folder into your current templates

You need to have the following packages installed for this to work properly
    sudo yum -y install libguestfs-xfs libguestfs-tools

Add to following to your deployment script

    -e /home/stack/templates/stig-fix.yaml \
    -e /home/stack/templates/post-deploy-stig.yaml \

chmod +x stig-overcloud.sh

Execute the stig-overcloud script
Get a cup of coffee
Deploy your stigged image
Get another cup of coffee

### Prereqs
You will need your RHN username, password and a pool id to get software from for the overcloud image


