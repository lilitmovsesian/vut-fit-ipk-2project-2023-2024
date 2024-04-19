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
    public abstract class Sniffer
    {
        protected static bool _tcp = false;
        protected static bool _udp = false;
        protected static int? _port = null;
        protected static int? _sourcePort = null;
        protected static int? _destinationPort = null;
        protected static bool _arp = false;
        protected static bool _ndp = false;
        protected static bool _icmp4 = false;
        protected static bool _icmp6 = false;
        protected static bool _igmp = false;
        protected static bool _mld = false;
        protected static int _numberOfPackets = 1;
        protected static ICaptureDevice? _device = null;
        public abstract void Start();

        protected static void ApplyFilters()
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
    }
}