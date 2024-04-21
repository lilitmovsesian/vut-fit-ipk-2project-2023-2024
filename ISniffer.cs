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
    /* Abstract class declaring abstract methods for Sniffer implementation*/
    public abstract class ISniffer
    {
        public abstract void Start();
        protected abstract void PacketHandler(object sender, PacketCapture e);   
        protected abstract void ApplyFilters();
    }
}