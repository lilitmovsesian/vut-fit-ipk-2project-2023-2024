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
    public abstract class ISniffer
    {
        public abstract void Start();
        protected abstract void PacketHandler(object sender, CaptureEventArgs e);   
        protected abstract void ApplyFilters();
    }
}