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
    /* A class that implements the methods of ISniffer 
    interface and provides the main functionality of sniffing. */
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
        /* Initializes a new instance of the Sniffer class. */
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

        /*Sets a cancel key press handle, opens a device in promiscuous mode,
        invokes a method for filtering, attaches the PacketHandler method to 
        the PacketArrival event and starts capturing.*/
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
            _device.Open(DeviceModes.Promiscuous, 1000);
            ApplyFilters();
            _device.OnPacketArrival += new PacketArrivalEventHandler(PacketHandler);
            _device.Capture();
        }

        /*A method for packet handling invoked whenever a packet is captured.*/
        protected override void PacketHandler(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            if (packet is PacketDotNet.NullPacket){
                return;
            }
            /*Extracting various types of packets.*/
            PacketDotNet.IPPacket ipPacket = packet.Extract<PacketDotNet.IPPacket>();
            PacketDotNet.TcpPacket tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            PacketDotNet.UdpPacket udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
            PacketDotNet.ArpPacket arpPacket = packet.Extract<PacketDotNet.ArpPacket>();
            PacketDotNet.EthernetPacket ethernetPacket = packet.Extract<PacketDotNet.EthernetPacket>();

            /*Formats and append time. */
            var time = PacketData.FormatTime(e.Header.Timeval.Date);
            var output = new StringBuilder();
            output.AppendLine($"timestamp: {time}");

            /*Extracting MAC addresses if Ethernet packet.*/
            if (ethernetPacket != null){
                var sourceMac = PacketData.FormatMac(ethernetPacket.SourceHardwareAddress.ToString());
                var destinationMac = PacketData.FormatMac(ethernetPacket.DestinationHardwareAddress.ToString());
                output.AppendLine($"src MAC: {sourceMac}");
                output.AppendLine($"dst MAC: {destinationMac}");
            }
            output.AppendLine($"frame length: {e.Data.Length} bytes");
            /*Handles arpPacket to extract the source and destination IP.*/
            if (arpPacket == null) {
                output.AppendLine($"src IP: {ipPacket.SourceAddress}");
                output.AppendLine($"dst IP: {ipPacket.DestinationAddress}");
            }
            else{
                output.AppendLine($"src IP: {arpPacket.SenderProtocolAddress}");
                output.AppendLine($"dst IP: {arpPacket.TargetProtocolAddress}");
            }
            /*Appends the port number if the captured packet is of TCP or UDP protocol.*/
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
            output.AppendLine(PacketData.FormatByteOffset(packet));

            Console.WriteLine(output.ToString());
            /*If the specified number of packets to capture is reached,
            stops the capture process and closes the device.*/
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

        /*Construct and applies a filter based on the arguments, construct
        the logical connections or/and between the filter options.*/
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
                    filter += " or (ip6 and icmp6 and (icmp6[0] = 133 or icmp6[0] = 134 or icmp6[0] = 135 or icmp6[0] = 136 or icmp6[0] = 137)) ";
                else {
                    filter += " (ip6 and icmp6 and (icmp6[0] = 133 or icmp6[0] = 134 or icmp6[0] = 135 or icmp6[0] = 136 or icmp6[0] = 137)) ";
                    or = true;
                }
            }
            if (_icmp4)
            {
                if (or)
                    filter += " or (ip and icmp) ";
                else {
                    filter += " (ip and icmp) ";
                    or = true;
                }
            }
            if (_icmp6)
            {
                if (or)
                    filter += " or (ip6 and icmp6 and (icmp6[0] = 128 or icmp6[0] = 129)) ";
                else {
                    filter += " (ip6 and icmp6 and (icmp6[0] = 128 or icmp6[0] = 129)) ";
                    or = true;
                }   
            }
            if (_igmp)
            {
                if (or)
                    filter += " or (ip and igmp) ";
                else {
                    filter += " (ip and igmp) ";
                    or = true;
                }  
            }
            if (_mld)
            {
                if (or)
                    filter += " or (ip6 and icmp6 and (icmp6[0] = 130 or icmp6[0] = 131 or icmp6[0] = 132 or icmp6[0] = 143)) ";
                else {
                    filter += " (ip6 and icmp6 and (icmp6[0] = 130 or icmp6[0] = 131 or icmp6[0] = 132 or icmp6[0] = 143)) ";
                    or = true;
                }  
            }
            if (_device != null && !string.IsNullOrEmpty(filter)){
                _device.Filter = filter;
            }
        }
    }
}