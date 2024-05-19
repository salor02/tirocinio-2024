# How to run the project

## Standard toolchain setup for Linux
1. Install prerequisites (Ubuntu/Debian):
```bash
sudo apt-get install git wget flex bison gperf python3 python3-pip python3-venv cmake ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0
```

2. Get ESP-IDF
```bash
mkdir -p ~/esp
cd ~/esp
git clone -b v5.2 --recursive https://github.com/espressif/esp-idf.git
```

3. Setup the tools
```bash
cd ~/esp/esp-idf
./install.sh esp32c6
```

## Build the project
1. You need to deal with the idf.py tool so you have to setup correctly the environment variables first
```bash
. $HOME/esp/esp-idf/export.sh
```
**Please note**: this command exports the correct environment variables just for the current terminal, so you have to run
this command everytime you need to use idf.py in another terminal 

2. Set the target of your build (this code has been tested on ESP32-C6)
idf.py set-target esp32c6

### Linux system
3. Build, flash and open serial monitor
```bash
idf.py build
idf.py -p <serial_port> flash monitor
```

### WSL2
3. In case your environment is on a WSL2, another tool is required since WSL2 does not offer USB support natively. Install ifdx:
```bash
curl https://git.io/JyBgj --create-dirs -L -o $HOME/bin/idfx && chmod u+x $HOME/bin/idfx
```

4. Build, flash and open serial monitor
```bash
idfx all <serial_port>
```
**Please note**: in this case the serial port will refer to a Windows serial port (COM1,COM2...)

More info:
https://docs.espressif.com/projects/esp-idf/en/v5.2/esp32c6/get-started/linux-macos-setup.html