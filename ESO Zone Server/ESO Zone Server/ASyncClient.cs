/**
 * Copyright (C) Luís Fonseca
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

using ESO_Zone_Server.Protocol;
using ESO_Zone_Server.Protocol.Messages;
using ESO_Zone_Server.Protocol.Packet;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace ESO_Zone_Server
{
    public class ASyncClient
    {
        public class ConnectionState
        {
            public const int BUFFER_SIZE = 4 * 1024;

            public Socket socket = null;

            public byte[] buffer = new byte[BUFFER_SIZE];

            public MemoryStream PacketsMemoryStream = new MemoryStream();

            public ConnectionState(Socket socket)
            {
                this.socket = socket;
            }
        }

        internal ConnectionState state;
        internal ZoneClient zoneClient;

        public ASyncClient(Socket socket)
        {
            state = new ConnectionState(socket);
            zoneClient = new ZoneClient();
            zoneClient.UserIPAddress = ((IPEndPoint)state.socket.RemoteEndPoint).Address;
            zoneClient.packetsToBeSent.CollectionChanged += (sender, eventArgs) =>
                {
                    if (!zoneClient.IsProcessingOrSendingPackets)
                    {
                        ASyncClient.SendPackets(this);
                    }
                };
        }

        public void ProcessRequest(byte[] receivedData)
        {
            try
            {
                lock (zoneClient.packetsToBeSent)
                {
                    zoneClient.IsProcessingOrSendingPackets = true;
                    zoneClient.packetsToBeSent.AddRange(
                            Zone.Process(zoneClient, receivedData));
                }
            }
            catch (Protocol.Packet.ZonePacket.NotEnoughBytesException ex)
            {
                zoneClient.IsProcessingOrSendingPackets = false;
                throw ex;
            }
            ASyncClient.SendPackets(this);
        }

        public static void SendPackets(ASyncClient client)
        {
            client.zoneClient.IsProcessingOrSendingPackets = true;
            if (client.zoneClient.packetsToBeSent.Count == 0)
            {
                client.zoneClient.IsProcessingOrSendingPackets = false;
                return;
            }

            MemoryStream memoryStream;
            lock (client.zoneClient.packetsToBeSent)
            {
                memoryStream =
                       client.zoneClient.packetsToBeSent.Aggregate(
                               new MemoryStream(),
                               (ms, packet) =>
                               {
                                   var packetBytes = packet.GetBytes(client.zoneClient.SecureKey);
                                   ms.Write(packetBytes, 0, packetBytes.Length);
                                   return ms;
                               });

                client.zoneClient.packetsToBeSent.Clear();
            }

            try
            {
                client.state.socket.BeginSend(
                        memoryStream.ToArray(), 0, memoryStream.ToArray().Length, SocketFlags.None,
                        new AsyncCallback(SendPacketsCallback), client);
            }
            catch (SocketException ex)
            {
                Log.Debug("ASyncClient", "Client closed socket.");
                Zone.ClientWentOffline(client);
            }

            client.zoneClient.IsProcessingOrSendingPackets = false;
        }

        private static void SendPacketsCallback(IAsyncResult ar)
        {
            var client = (ASyncClient)ar.AsyncState;
            Socket socket = client.state.socket;

            int bytesSent = socket.EndSend(ar);
            Log.Inform("AsyncClient", "Sent " + bytesSent + " bytes to client");
        }
    }
}
