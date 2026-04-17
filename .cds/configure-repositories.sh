echo "deb [trusted=yes] http://last-public-canonical-ubuntu-archive.snap.mirrors.ovh.net/ubuntu focal main universe multiverse restricted" >/etc/apt/sources.list.d/ubuntu-ovh.list
echo "deb [trusted=yes] http://last-public-canonical-ubuntu-archive.snap.mirrors.ovh.net/ubuntu focal-security main universe multiverse restricted" >>/etc/apt/sources.list.d/ubuntu-ovh.list
echo "deb [trusted=yes] http://last-public-canonical-ubuntu-archive.snap.mirrors.ovh.net/ubuntu focal-updates main universe multiverse restricted" >>/etc/apt/sources.list.d/ubuntu-ovh.list
echo "deb [trusted=yes] http://read:${CDS_PROJ_PRIVATE_OVH_OBJECTSTORAGE_OPENIO_READ_PASSWORD}@last-private-ovh-objectstorage-openio.snap-priv.mirrors.ovh.net/ubuntu focal/main main" >/etc/apt/sources.list.d/snapmirror-ovh-objectstorage-openio.list
echo "deb [trusted=yes] http://last-public-ovh-pcs.snap.mirrors.ovh.net/ubuntu focal main" >/etc/apt/sources.list.d/obsto.list

# Disable the VM-provided repositories, use only the repos provided above
sed -i -E \
    -e 's/^(deb .*\.ubuntu.com.*)$/#\1/' \
    /etc/apt/sources.list.d/* /etc/apt/sources.list

# Docker repo for docker compose plugin should be removed after https://jira.ovhcloud.tools/browse/CORDEV-2545 completion
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
    "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" |
    sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
