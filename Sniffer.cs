using System;
using System.Linq;
using System.Collections.Generic;
using SharpPcap;
using PacketDotNet;
using System;
using System.Text;
using System.Net;
using SharpPcap.LibPcap;
using System.Net.NetworkInformation;

namespace ipkSniffer
{
    public class Sniffer : ISniffer
    {
        private bool _tcp = false;
        private bool _udp = false;
        private int? _port = null;
        private int? _sourcePort = null;
        private int? _destinationPort = null;
        private bool _arp = false;
        private bool _ndp = false;
        private bool _icmp4 = false;
        private bool _icmp6 = false;
        private bool _igmp = false;
        private bool _mld = false;
        private int _numberOfPackets = 1;
        private ICaptureDevice? _device = null;
        private int _counter = 0;
        public Sniffer(ICaptureDevice device, bool tcp, bool udp, int? port, int? sourcePort, int? destinationPort, bool arp, bool ndp, bool icmp4, bool icmp6, bool igmp, bool mld, int numberOfPackets)
        {
            _device = device;
            _tcp = tcp;
            _udp = udp;
            _port = port;
            _sourcePort = sourcePort;
            _destinationPort = destinationPort;
            _arp = arp;
            _ndp = ndp;
            _icmp4 = icmp4;
            _icmp6 = icmp6;
            _igmp = igmp;
            _mld = mld;
            _numberOfPackets = numberOfPackets;
        }

        public override void Start()
        {
            if (_device == null)
            {
                Console.Error.WriteLine("Error: Failed to find the specified interface.");
                Environment.Exit(1);
            }
            Console.CancelKeyPress += (sender, e) =>
            {
                _device.StopCapture();
                _device.Close();
                Environment.Exit(0);
            };
            _device.Open(DeviceMode.Promiscuous, 100);
            ApplyFilters();
            _device.OnPacketArrival += PacketHandler;
            _device.StartCapture();
        }

        protected override void PacketHandler(object sender, CaptureEventArgs e)
        {
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if (packet is PacketDotNet.NullPacket){
                return;
            }
            PacketDotNet.IPPacket ipPacket = packet.Extract<PacketDotNet.IPPacket>();
            PacketDotNet.TcpPacket tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            PacketDotNet.UdpPacket udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
            PacketDotNet.ArpPacket arpPacket = packet.Extract<PacketDotNet.ArpPacket>();
            PacketDotNet.EthernetPacket ethernetPacket = packet.Extract<PacketDotNet.EthernetPacket>();

            var time = PacketData.FormatTime(e.Packet.Timeval.Date);
            var output = new StringBuilder();

            output.AppendLine($"timestamp: {time}");

            if (ethernetPacket != null){
                var sourceMac = PacketData.FormatMac(ethernetPacket.SourceHardwareAddress.ToString());
                var destinationMac = PacketData.FormatMac(ethernetPacket.DestinationHardwareAddress.ToString());
                output.AppendLine($"src MAC: {sourceMac}");
                output.AppendLine($"dst MAC: {destinationMac}");
            }
            output.AppendLine($"frame length: {e.Packet.Data.Length} bytes");
            if (arpPacket == null) {
                output.AppendLine($"src IP: {ipPacket.SourceAddress}");
                output.AppendLine($"dst IP: {ipPacket.DestinationAddress}");
            }
            else{
                output.AppendLine($"src IP: {arpPacket.SenderProtocolAddress}");
                output.AppendLine($"dst IP: {arpPacket.TargetProtocolAddress}");
            }
            if (tcpPacket != null)
            {
                output.AppendLine($"src port: {tcpPacket.SourcePort}");
                output.AppendLine($"dst port: {tcpPacket.DestinationPort}");
            }
            else if (udpPacket != null)
            {
                output.AppendLine($"src port: {udpPacket.SourcePort}");
                output.AppendLine($"dst port: {udpPacket.DestinationPort}");
            }
            
            output.AppendLine();
            output.AppendLine(PacketData.PrintByteOffset(packet));

            Console.WriteLine(output.ToString());
            if (++_counter != _numberOfPackets)
            {
                return;
            }
            
            if (_device != null){
                _device.StopCapture();
                _device.Close();
            }
            Environment.Exit(0);
        }

        protected override void ApplyFilters()
        {
            var filter = "";
            bool or = false;
            if (_tcp || _udp)
            {
                filter += "(";
                if (_tcp && !_udp)
                {
                    filter += " (ip or ip6) and tcp ";
                }
                if (_udp && !_tcp)
                {
                    filter += " (ip or ip6) and udp ";
                }
                if (_udp && _tcp)
                {
                    filter += " (ip or ip6) and (tcp or udp) ";
                }
                if (_port != null)
                {
                    filter += " and port " + _port + " ";
                }
                if (_sourcePort != null)
                {
                    filter += $" and src port {_sourcePort} ";
                }
                if (_destinationPort != null)
                {
                    filter += $" and dst port {_destinationPort} ";
                }
                filter += ")";
                or = true;
            }
            
            if (_arp)
            {
                if (or)
                    filter += " or arp ";
                else {
                    filter += " arp ";
                    or = true;
                }
            }
            if (_ndp)
            {
                if (or)
                    filter += " or (icmp6 and (icmp6[0] = 133 or icmp6[0] = 134 or icmp6[0] = 135 or icmp6[0] = 136 or icmp6[0] = 137)) ";
                else {
                    filter += " (icmp6 and (icmp6[0] = 133 or icmp6[0] = 134 or icmp6[0] = 135 or icmp6[0] = 136 or icmp6[0] = 137)) ";
                    or = true;
                }
            }
            if (_icmp4)
            {
                if (or)
                    filter += " or icmp ";
                else {
                    filter += " icmp ";
                    or = true;
                }
            }
            if (_icmp6)
            {
                if (or)
                    filter += " or icmp6 ";
                else {
                    filter += " icmp6 ";
                    or = true;
                }   
            }
            if (_igmp)
            {
                if (or)
                    filter += " or igmp ";
                else {
                    filter += " igmp ";
                    or = true;
                }  
            }
            if (_mld)
            {
                if (or)
                    filter += " or (icmp6 and (icmp6[0] = 130 or icmp6[0] = 131 or icmp6[0] = 132 or icmp6[0] = 143)) ";
                else {
                    filter += " (icmp6 and (icmp6[0] = 130 or icmp6[0] = 131 or icmp6[0] = 132 or icmp6[0] = 143)) ";
                    or = true;
                }  
            }
            if (_device != null && !string.IsNullOrEmpty(filter)){
                _device.Filter = filter;
            }
        }
    }
}