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
    public class PacketData
    {
        /*A method that separated MAC address with colon.*/
        public static string FormatMac(string macAddress)
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

        /*A method to format date, time and timezone correctly.*/
        public static string FormatTime(DateTime time)
        {
            var formattedTime = new StringBuilder();
            var utcOffset = (TimeZoneInfo.Local.GetUtcOffset(DateTime.Now)).ToString().Substring(0, 5);
            var month = (time.Month).ToString();
            formattedTime.Append($"{time.Year}-{time.Month.ToString("00")}-{time.Day.ToString("00")}T{time.Hour.ToString("00")}:{time.Minute.ToString("00")}:{time.Second.ToString("00")}.{time.Millisecond.ToString("000")}+{utcOffset}");
            return formattedTime.ToString();
        }

        /* A method for creating a string of packet data. */
        public static string FormatByteOffset(PacketDotNet.Packet packet)
        {
            var data = packet.BytesSegment.Bytes;
            var output = new StringBuilder();
            output.AppendLine("byte_offset: ");
            /* Loop through data in 16 bytes, then loop through each byte. */
            for (int i = 0; i < data.Length; i += 16)
            {
                /* Appends the byte offset in hexadecimal format. */
                output.Append($"0x{i:x4}: ");
                for (int j = 0; j < 16 && i + j < data.Length; j++)
                {
                    /* Appends the hexadecimal representation of bytes.*/
                    output.Append($"{data[i+j]:x2} ");
                } 
                if (data.Length - i < 16)
                {
                    /*Alligns the last row. */
                    output.Append(new string(' ', 3 * (16 - (data.Length - i))));
                }
                output.Append(" ");
                /* Appends ASCII representation of bytes to the string. */
                for (int j = 0; j < 16 && i + j < data.Length; j++)
                {
                    char c = (char)data[i + j];
                    /*Appends dot in case of non-printable characters.*/
                    output.Append((c >= 32 && c <= 126) ? c : '.');
                }
                output.AppendLine();
            }
            return output.ToString();
        }
    }
}