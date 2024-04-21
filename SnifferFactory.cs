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
    public class SnifferFactory
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
        private static ICaptureDevice? _device = null;
        
        /*This method prints the available interfaces in case of unspecified
        interface or finds the device if specified. Then it creates an instance 
        of a Sniffer class based on the arguments and returns it.*/
        public static Sniffer CreateSniffer(string[] args)
        {
            ParseArguments(args);

            var devices = CaptureDeviceList.Instance;
            if (_showInterfaces)
            {
                foreach (var dev in devices)
                {
                    Console.WriteLine(dev.Name.PadRight(20, ' ') + " " + dev.Description);
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
                Console.Error.WriteLine("Error: Failed to find the specified interface.");
                Environment.Exit(1);
            }
            return new Sniffer(_device, _tcp, _udp, _port, _sourcePort, _destinationPort, _arp, _ndp, _icmp4, _icmp6, _igmp, _mld, _numberOfPackets);
        }

        /*This method manually parses CLI arguments and sets variables. */
        private static void ParseArguments(string[] args)
        {
            /* If no arguments provided, show interfaces*/
            if (args.Length == 0){
                _showInterfaces = true;
            }
            /* If only one argument is provided and it is not -i or --interface, show error. */
            if (args.Length == 1 && (args[0] != "-i" && args[0] != "--interface")){
                Console.Error.WriteLine("Error: Interface unspecified.");
                Environment.Exit(1);
            }
            /* A loop through arguments.*/
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
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-")) {
                            _port = int.Parse(args[i + 1]);
                        }
                        else{
                            Console.Error.WriteLine("Error: Invalid arguments.");
                            Environment.Exit(1);
                        }
                        break;
                    case "--port-source":
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-")) {
                            _sourcePort = int.Parse(args[i + 1]);
                        }
                        else{
                            Console.Error.WriteLine("Error: Invalid arguments.");
                            Environment.Exit(1);
                        }
                        break;
                    case "--port-destination":
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-")) {
                            _destinationPort = int.Parse(args[i + 1]);
                        }
                        else{
                            Console.Error.WriteLine("Error: Invalid arguments.");
                            Environment.Exit(1);
                        }
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
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-")) {
                            _numberOfPackets = int.Parse(args[i + 1]);
                        }
                        else{
                            Console.Error.WriteLine("Error: Invalid arguments.");
                            Environment.Exit(1);
                        }
                        break;
                    default:
                        break;
                }
            }
            /*If interface is unspecified but there are other arguments, print error. */
            if (args.Length > 1 && _interfaceName == null){
                Console.Error.WriteLine("Error: Interface unspecified.");
                Environment.Exit(1);
            }
            /*If port is set with incorrect protocol filtering, print error.*/
            if ((_port != null || _destinationPort != null || _sourcePort != null) && !_tcp && !_udp){
                Console.Error.WriteLine("Error: --tcp or --udp argument should be specified.");
                Environment.Exit(1);
            }
            /*If port arguments are set incorrectly, print error.*/
            if (_port != null && (_destinationPort != null || _sourcePort != null)){
                Console.Error.WriteLine("Error: -p argument cannot be specified with --port-source and --port-destination arguments.");
                Environment.Exit(1);
            }
        }
    }
}