# Automatically configure Cntlm based on internal or external network on macOS

This setup is used to automatically execute `cntlm` using a configuration depending on the current network. It uses Apple's [Kerberos Single Sign On Extension](doc/Kerberos_Single_Sign_on_Extension_User_Guide.pdf).

## How to use

- copy the content of ["kerberos" folder](./kerberos/) in a folder somewhere in your system and `cd` into that folder.
- copy the `cntlm` executable in the same folder.
- edit `cntlm_internal.conf` to match the configuration for your internal (corporate) network.
- the file `cntlm_external.conf` is configured as a passthru for the internet.
- compile `listener.swift` with the command `swiftc listener.swift`.
- run `./install.sh`. This installs a `plist` configuration file and starts the `cntlm` process.

Now `cntlm` is running with the configuration of your current network. As soon as the network changes, it will restart `cntlm` with the new configuration.

If you need to uninstall this configuration, run `./uninstall.sh`. It will stop the `cntlm` process and remove the `plist` configuration file.
