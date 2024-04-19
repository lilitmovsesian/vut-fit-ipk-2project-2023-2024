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
    class Program
    {
        static void Main(string[] args)
        {
            Sniffer sniffer = SnifferFactory.CreateSniffer(args);
            sniffer.Start();
        }
    }
}