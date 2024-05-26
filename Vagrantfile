Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

   config.vm.provider "virtualbox" do |vb|
     vb.memory = "8192"
	 vb.cpus = 4
   end
  config.vm.provision "shell", inline: <<-SHELL
     apt-get update
     apt-get install -y build-essential
     apt-get install -y  libssl-dev
     apt-get install -y autoconf
     apt-get install -y gdb
     apt-get install -y libcurl4-openssl-dev
     apt-get install -y cmake
   SHELL
end
