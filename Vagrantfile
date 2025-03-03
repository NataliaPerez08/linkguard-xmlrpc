Vagrant.configure("2") do |config|
  # Configuración para VM1
  config.vm.define "vm1" do |vm1|
    vm1.vm.box = "ubuntu/focal64"
    vm1.vm.network "private_network", ip: "192.168.50.2", type: "dhcp"
    # Copy directory from host to temporary location in VM
    #vm1.vm.provision "file", source: "./OrquestradorXmlrpc", destination: "/tmp/OrquestradorXmlrpc"
    vm1.vm.provision "shell", inline: <<-SHELL
      sudo apt update
      sudo apt install -y wireguard
      sudo mkdir -p /etc/wireguard
      sudo chmod 600 /etc/wireguard
    SHELL
  end
end

