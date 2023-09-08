# TeleVM
TeleVM is a lightweight virtual machine for RISC-V architecture, with the advantages of low overhead and high security. It can be used in scenarios such as serverless and secure containers.  


## How to start
### Preparation
Before building TeleVM, make sure that Rust language and Cargo have already been installed. If you want to cross compile TeleVM on the x86 platform, you also need to install RISC-V GNU compiler toolchain. you can find installation guidance via following link:   
https://github.com/riscv-collab/riscv-gnu-toolchain  


### Build TeleVM
To build TeleVM, clone the project and build it first:  
```
git clone https://github.com/ltz0302/TeleVM
cd televm
cargo build
```
Now you can find TeleVM binary in target/riscv64gc-unknown-linux-gnu/debug  

### Run a VM
TeleVM needs to run on RISC-V CPU that support H extension or in RISC-V environments simulated by QEMU. Run the following command to check if the CPU supports H extension.  
```
cat /proc/cpuinfo
```
If the h character is included in the isa option, the CPU supports the H extension. 


In addition, TeleVM also relies on KVM. Run the following command to check if the KVM module is loaded.  
```
ls /dev | grep kvm
```
If kvm is output, it indicates that it has been loaded.  


In order to start the virtual machine, it is also necessary to prepare the RISC-V kernel image and rootfs image.  
Start a virtual machine using the following command.    
```
# Start televm  
./target/riscv64gc-unknown-linux-gnu/debug/televm \
  -machine microvm \
  -smp 1 \
  -m 2g \
  -kernel /path/to/kernel \
  -drive id=rootfs,file=/path/to/rootfs \
  -device virtio-blk-device,drive=rootfs,id=blk1 \
  -serial stdio \
  -append "root=/dev/vda rw console=console=ttyS0" \
  -qmp unix:/path/to/socket,server,nowait
```