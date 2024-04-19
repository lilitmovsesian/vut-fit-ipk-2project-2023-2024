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
    public class LiveSniffer : Sniffer
    {
        private static int _counter = 0;
        public LiveSniffer(ICaptureDevice device, bool tcp, bool udp, int? port, int? sourcePort, int? destinationPort, bool arp, bool ndp, bool icmp4, bool icmp6, bool igmp, bool mld, int numberOfPackets)
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

        private static void PacketHandler(object sender, CaptureEventArgs e)
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
    }
}