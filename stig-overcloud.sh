#!/bin/bash
echo "#################################################################################"
echo "# These are instructions for how to build a DISA STIG Compliant overcloud image #"
echo "# This will work with OSP11  - please contact donny@redhat.com with issues      #"
echo "#################################################################################"
read -p "RHN Username: " name
read -s -p "RHN password: (doesn't echo)" password
read -p "Subscritpion pool id: " pool_id
for i in /usr/share/rhosp-director-images/overcloud-full-latest-11.0.tar /usr/share/rhosp-director-images/ironic-python-agent-latest-11.0.tar; do tar -xvf $i; done
virt-customize -a overcloud-full.qcow2 --run-command "subscription-manager register --username=$name --password=$password"
virt-customize -a overcloud-full.qcow2 --run-command "subscription-manager attach --pool $pool_id"
virt-customize -a overcloud-full.qcow2 --run-command 'subscription-manager repos --disable "*"'
virt-customize -a overcloud-full.qcow2 --run-command 'subscription-manager repos --enable rhel-7-server-rpms'
virt-customize -a overcloud-full.qcow2 --run-command 'yum -y install openscap-scanner scap-security-guide aide'
#############################################
# The Next command will generate a          #
# bash script to run on our overcloud image #
#############################################
virt-customize -a overcloud-full.qcow2 --run-command 'oscap xccdf generate fix --template urn:xccdf:fix:script:sh --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --output /opt/overcloud-remediation.sh /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml'
sudo LIBGUESTFS_BACKEND=direct  guestmount -a overcloud-full.qcow2 -i /mnt/guest
sudo cp /mnt/guest/opt/overcloud-remediation.sh .
sudo guestunmount /mnt/guest
##############################################
# I would like to find a better way to       #
# pull the fips stuff from the stig,         #
# but I'm in a hurry so this will do for now #
##############################################
sudo chown stack:stack overcloud-remediation.sh
sed -i '/yum -y update/d' overcloud-remediation.sh
sed -i '/package_command install dracut-fips/,+20 d' overcloud-remediation.sh
sed -i "s/service_command enable firewalld/service_command disable firewalld/g" overcloud-remediation.sh
cat ssg-supplemental.sh >> overcloud-remediation.sh
virt-customize -a overcloud-full.qcow2 --upload overcloud-remediation.sh:/opt
virt-customize -a overcloud-full.qcow2 --run-command 'chmod +x /opt/overcloud-remediation.sh'
virt-customize -v -a overcloud-full.qcow2 --run-command '/opt/overcloud-remediation.sh'
virt-customize -a overcloud-full.qcow2 --delete '/opt/overcloud-remediation.sh'
virt-customize -a overcloud-full.qcow2 --run-command 'subscription-manager remove --all'
virt-customize --selinux-relabel -a overcloud-full.qcow2 --run-command 'subscription-manager unregister'
source ~/stackrc
openstack overcloud image upload --update-existing --image-path $(pwd)

