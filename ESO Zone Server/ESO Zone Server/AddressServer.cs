using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ESO_Zone_Server
{
    /// <summary>
    /// This server is responsible to send the IP address of a client.
    /// This is to get a 'real' external address.
    /// 
    /// To test locally, add 'hostPort=2301' to AoM user.cfg file.
    /// </summary>
    public class AddressServer
    {
        public void Start()
        {
            IPHostEntry ipHostInfo = Dns.GetHostEntry("192.168.1.75");
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 2300);
            UdpClient udpClient = new UdpClient(localEndPoint);

            Log.Inform("AddressServer", "Started and is working...");

            while (true)
            {
                IPEndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                byte[] data = udpClient.Receive(ref sender);

                switch (data[0])
                {
                    case 9:
                        byte[] address = sender.Address.GetAddressBytes();

                        MemoryStream reply = new MemoryStream();
                        reply.WriteByte(9);
                        reply.Write(new byte[] {0x02, 0x00, 0xd9, 0x49}, 0, 4); // still unkown, but this seems to work
                        reply.Write(address, 0, 4);
                        reply.Write(new byte[8], 0, 8);
                        reply.Write(data, 1, 4);

                        udpClient.Send(reply.ToArray(), 21, sender);
                        Log.Inform("AddressServer", "Got IP request from [" + sender.Address + "]");
                        continue;
                    case 10:
                        // Reply with the same message
                        udpClient.Send(data, data.Length, sender);
                        continue;
                }
            }
        }
    }
}
