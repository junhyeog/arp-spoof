#pragma once
#include <libnet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arphdr.h"
#include "ethhdr.h"
#include "iphdr.h"

struct EthArpPacket {
  EthHdr eth_;
  ArpHdr arp_;
};

struct EthIpPacket {
  EthHdr eth_;
  IpHdr ip_;
};

struct ArpSpoofing final {
  int getMacByInterface(const char *ifname, uint8_t *mac_addr);
  int getIpByInterface(const char *ifname, uint8_t *ip_addr);
  int getMacByIp(const char *ifname, Ip ip_addr, uint8_t *mac_addr);
  EthArpPacket get_arp_packet(Mac attacker_mac, Mac sender_mac, Ip sender_ip,
                              Ip target_ip);
  int attack_arp_spoofing(pcap_t *handle, EthArpPacket packet);
  int arp_infect(pcap_t *handle, Mac attacker_mac, Mac sender_mac, Ip sender_ip,
                 Ip target_ip);
  bool check_recover_packet(const u_char *received_packet, Mac sender_mac,
                            Mac target_mac);
  // for relay
  bool check_spoofed_packet(const u_char *packet, Mac sender_mac,
                            Mac attacker_mac);
  int relay_spoofed_packet(pcap_t *handle, struct pcap_pkthdr *,
                           const u_char *packet, Mac attacker_mac,
                           Mac target_mac);
  int arp_spoofing(char *ifname, pcap_t *handle, Ip sender_ip, Ip target_ip);
};
