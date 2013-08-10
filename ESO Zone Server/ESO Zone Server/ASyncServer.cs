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
    public class ASyncServer
    {
        public static ManualResetEvent waitForNewConnection = new ManualResetEvent(false);

        public static void Start(object port)
        {
            IPHostEntry ipHostInfo = Dns.GetHostEntry("192.168.1.88");
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, (int)port);

            byte[] bytes = new Byte[1024];
            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(100);

                while (true)
                {
                    waitForNewConnection.Reset();
                    listener.BeginAccept(new AsyncCallback(AcceptCallback), listener);
                    Log.Inform("ASyncServer", "Waiting for next client...");
                    waitForNewConnection.WaitOne();
                }

            }
            catch (Exception ex)
            {
                Log.Debug("ASyncServer", ex.ToString());
            }
        }

        public static void AcceptCallback(IAsyncResult ar)
        {
            waitForNewConnection.Set();

            // Get the socket that handles the client request.
            Socket listener = (Socket) ar.AsyncState;
            Socket handler = listener.EndAccept(ar);

            var client = new ASyncClient();
            client.state.socket = handler;
            if (((IPEndPoint)handler.LocalEndPoint).Port >= Zone.CHAT_PORT)
            {
                client.zoneClient.IsOnLobby = true;
            }
            Log.Inform("ASyncServer", "New connection setup. Waiting for client first message.");
            handler.BeginReceive(client.state.buffer, 0, client.state.buffer.Length, 0, new AsyncCallback(ReadCallback), client);
        }

        public static void ReadCallback(IAsyncResult ar)
        {
            // Retrieve the state object and the handler socket
            // from the asynchronous state object.
            var client = (ASyncClient)ar.AsyncState;
            Socket handler = client.state.socket;

            // Read data from the client socket. 
            int bytesRead = handler.EndReceive(ar);

            Log.Inform("ASyncServer", "Got client message, " + bytesRead + " bytes read.");
            if (bytesRead > 0)
            {
                client.state.PacketsMemoryStream.Write(client.state.buffer, 0, bytesRead);
                try
                {
                    byte[] recievedData = client.state.PacketsMemoryStream.ToArray();
                    client.ProcessRequest(recievedData);
                    client.state.PacketsMemoryStream = new MemoryStream();
                }
                catch (Protocol.Packet.ZonePacket.NotEnoughBytesException ex)
                {
                }
                finally
                {
                    Log.Inform("ASyncServer", "Waiting for client reply.");
                    handler.BeginReceive(client.state.buffer, 0, client.state.buffer.Length, SocketFlags.None, new AsyncCallback(ReadCallback), client);
                }
            }
            else
            {
                // Client doesn't want to send anything else now, gracefull disconnection?
                if (handler.Connected)
                {
                    handler.BeginReceive(client.state.buffer, 0, client.state.buffer.Length, SocketFlags.None, new AsyncCallback(ReadCallback), client);
                }
            }
        }
    }
}
