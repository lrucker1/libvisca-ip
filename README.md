# libvisca-ip

This is a libvisca library with VISCA over TCP and UDP. This branch also supports PTZOptics variations, and adds a plugin to support writing PacketSender import files.

## Build
Use cmake to build this library as below.
```
mkdir build
cd build
cmake ..
```

## Firewall
For VISCA over UDP, you might need to accept income port 52381.
This is because the PTZ cameras from Sony ignores the source port and always return packet to UDP 52381 port.
For iptables users, run this command or equivalent.
```
sudo iptables -I INPUT 1 -j ACCEPT -p udp --dport 52381
```
For firewalld users, run this command.
```
firewall-cmd --add-port 52381/udp
```

## Acknowledge

- https://github.com/mkoppanen/libVISCA2
  This is the base library.
- http://damien.douxchamps.net/libvisca/
  This is the original library of libvisca.

## Dependencies
- https://github.com/lrucker1/iniparser 
  This is a minor variant; PacketSender requires case-sensitive keys.
