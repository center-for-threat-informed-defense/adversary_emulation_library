# Install pre-reqs
sudo apt update -y
sudo apt install curl git -y

# Install Pupy RAT
git clone --recursive https://github.com/n1nj4sec/pupy.git
cd pupy
./install.sh
sed 's/9000:9000/1234:1234/g' pupy/conf/docker-compose.yml > /tmp/docker-compose.yml
cp /tmp/docker-compose.yml pupy/conf/docker-compose.yml

# Install Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall