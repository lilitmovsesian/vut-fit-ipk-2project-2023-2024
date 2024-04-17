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

class Program
{
    private static string? _interfaceName = null;
    private static bool _showInterfaces = false;
    private static bool _tcp = false;
    private static bool _udp = false;
    private static int? _port = null;
    private static int? _sourcePort = null;
    private static int? _destinationPort = null;
    private static bool _arp = false;
    private static bool _ndp = false;
    private static bool _icmp4 = false;
    private static bool _icmp6 = false;
    private static bool _igmp = false;
    private static bool _mld = false;
    private static int _numberOfPackets = 1;
    private static int _counter = 0;
    private static ICaptureDevice? _device = null;
    static void Main(string[] args)
    {
        for (int i = 0; i < args.Length; i++){
            switch (args[i]){
                case "-i":
                case "--interface":
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-")) {
                        _interfaceName = args[i + 1];
                    }
                    else {
                        _showInterfaces = true;
                    }
                    break;
                case "-p":
                    _port = int.Parse(args[i + 1]);
                    break;
                case "--port-source":
                    _sourcePort = int.Parse(args[i + 1]);
                    break;
                case "--port-destination":
                    _destinationPort = int.Parse(args[i + 1]);
                    break;
                case "--tcp":
                case "-t":
                    _tcp = true;
                    break;
                case "--udp":
                case "-u":
                    _udp = true;
                    break;
                case "--arp":
                    _arp = true;
                    break;
                case "--icmp4":
                    _icmp4 = true;
                    break;
                case "--icmp6":
                    _icmp6 = true;
                    break;
                case "--igmp":
                    _igmp = true;
                    break;
                case "--mld":
                    _mld = true;
                    break;
                case "--ndp":
                    _ndp = true;
                    break;
                case "-n":
                    _numberOfPackets = int.Parse(args[i + 1]);
                    break;
                default:
                    break;
            }
        }
        var devices = CaptureDeviceList.Instance;
        if (_showInterfaces)
        {
            foreach (var dev in devices)
            {
                Console.WriteLine(dev.Name);
            }
            Environment.Exit(0);
        }
        foreach (var dev in devices)
        {
            if (_interfaceName != null && dev.Name != null) {
                if (_interfaceName.Equals(dev.Name, StringComparison.OrdinalIgnoreCase)) {
                    _device = dev;
                    break;
                }
            }
        }
        if (_device == null)
        {
            Console.WriteLine("Failed to find the specified interface.");
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

    static void ApplyFilters()
    {
        var filter = "";
        bool or = false;
        if (_tcp || _udp)
        {
            filter += "(";
            if (_tcp && !_udp)
            {
                filter += " tcp ";
            }
            if (_udp && !_tcp)
            {
                filter += " udp ";
            }
            if (_udp && _tcp)
            {
                filter += " (tcp or udp) ";
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
    static void PacketHandler(object sender, CaptureEventArgs e)
    {
        var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
        if (packet is PacketDotNet.NullPacket){
            return;
        }
        PacketDotNet.IPPacket ip = packet.Extract<PacketDotNet.IPPacket>();
        PacketDotNet.TcpPacket tcp = packet.Extract<PacketDotNet.TcpPacket>();
        PacketDotNet.UdpPacket udp = packet.Extract<PacketDotNet.UdpPacket>();
        PacketDotNet.ArpPacket arp = packet.Extract<PacketDotNet.ArpPacket>();
        PacketDotNet.EthernetPacket ethernetPacket = packet.Extract<PacketDotNet.EthernetPacket>();

        var time = FormatTime(e.Packet.Timeval.Date);
        var output = new StringBuilder();

        output.AppendLine($"timestamp: {time}");

        if (ethernetPacket != null){
            var sourceMac = FormatMac(ethernetPacket.SourceHardwareAddress.ToString());
            var destinationMac = FormatMac(ethernetPacket.DestinationHardwareAddress.ToString());
            output.AppendLine($"src MAC: {sourceMac}");
            output.AppendLine($"dst MAC: {destinationMac}");
        }
        output.AppendLine($"frame length: {e.Packet.Data.Length} bytes");
        if (arp == null) {
            output.AppendLine($"src IP: {ip.SourceAddress}");
            output.AppendLine($"dst IP: {ip.DestinationAddress}");
        }
        if (tcp != null)
        {
            AppendTcpDetails(output, tcp);
        }
        else if (udp != null)
        {
            AppendUdpDetails(output, udp);
        }
        
        output.AppendLine();
        output.AppendLine(PrintHex(packet));

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

    static string FormatMac(string macAddress)
    {
        var formattedMac = new StringBuilder();
        int j = 0;
        for (int i = 0; i < macAddress.Length; i++)
        {
            if (j==2){
                formattedMac.Append(":");
                j = 0;
            }
            formattedMac.Append(char.ToLower(macAddress[i]));
            j++;
        }
        
        return formattedMac.ToString();
    }

    static void AppendTcpDetails(StringBuilder output, PacketDotNet.TcpPacket tcpPacket)
    {
        output.AppendLine($"src port: {tcpPacket.SourcePort}");
        output.AppendLine($"dst port: {tcpPacket.DestinationPort}");
    }

    static void AppendUdpDetails(StringBuilder output, PacketDotNet.UdpPacket udpPacket)
    {
        output.AppendLine($"src port: {udpPacket.SourcePort}");
        output.AppendLine($"dst port: {udpPacket.DestinationPort}");
    }

    static string FormatTime(DateTime time)
    {
        var formattedTime = new StringBuilder();
        var utcOffset = (TimeZoneInfo.Local.GetUtcOffset(DateTime.Now)).ToString().Substring(0, 5);
        var month = (time.Month).ToString();
        formattedTime.Append($"{time.Year}-{time.Month.ToString("00")}-{time.Day.ToString("00")}T{time.Hour.ToString("00")}:{time.Minute.ToString("00")}:{time.Second.ToString("00")}.{time.Millisecond.ToString("000")}+{utcOffset}");
        return formattedTime.ToString();
    }

   static string PrintHex(PacketDotNet.Packet packet)
    {
        var data = packet.Bytes;
        var output = new StringBuilder();
        for (int i = 0; i < data.Length; i += 16)
        {
            output.Append($"0x{i:x4}: ");
            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                output.Append($"{data[i + j]:x2} ");
            }
            if (data.Length - i < 16)
            {
                output.Append(new string(' ', 3 * (16 - (data.Length - i))));
            }
            output.Append(" ");
            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                char c = (char)data[i + j];
                output.Append((c >= 32 && c <= 126) ? c : '.');
            }
            output.AppendLine();
        }
        return output.ToString();
    }
}