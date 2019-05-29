# LibVMI-extensions for Bareflank
Hypervisor extensions to Bareflank to support introspecting the host with LibVMI

# Compilation and usage

```
git clone https://github.com/libvmi/bareflank_libvmi_extension --recursive
cd bareflank_libvmi_extension
mkdir build && cd build
cmake ../hypervisor -DDEFAULT_VMM=bareflank_libvmi_extension -DEXTENSION=../libvmi_extension
make -j<#of cores + 1>
```

To load & launch the hypervisor run:
```
sudo make driver_quick
sudo make quick
```

You can verify the hypervisor is properly loaded by running:
```
make ack
```
