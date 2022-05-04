# update package repository
apt-get update -y

# remove this package because it conflicts with terminator
sudo apt remove mitmproxy -y

# needed for terminal pane management
apt-get install terminator -y