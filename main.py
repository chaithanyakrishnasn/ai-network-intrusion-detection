from capture.sniffer import PacketSniffer

if __name__ == "__main__":
    sniffer = PacketSniffer(
        interface=r"\Device\NPF_{A0961EF5-BB21-4ACE-B746-94608AFFC560}"
    )
    sniffer.start()
