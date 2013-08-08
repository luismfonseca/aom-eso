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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.IO;
using ESOSniffer.Protocol;

namespace ESOSniffer
{
    public class Connections
    {
        public class StateObject
        {
            public Socket workSocket = null;
            public Socket esoSocket = null;

            public int bytesRead;
            public byte[] buffer = new byte[1024 * 16];
        }

        public static ManualResetEvent allDone = new ManualResetEvent(false);
        public delegate void LogHandler(String logText);
        public static LogHandler logHandler;

        private static FlowAnalyzer flowAnalyzer = new FlowAnalyzer();
        private static int requestGotCount = 0;
        private static int requestSentCount = 0;

        public static void Start()
        {
            // Data buffer for incoming data.
            byte[] bytes = new Byte[1024];

            // Establish the local endpoint for the socket.
            IPHostEntry ipHostInfo = Dns.GetHostEntry("192.168.1.88");
            IPAddress ipAddress = ipHostInfo.AddressList[0]; //1
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 28805);
            logHandler("[Connections] Starting client listenner at " + localEndPoint.Address + ": " + localEndPoint.Port);

            // Create a TCP/IP socket.
            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and listen for incoming connections.
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(100);

                while (true)
                {
                    allDone.Reset();
                    logHandler("[Connections] Waiting for a connection...");

                    listener.BeginAccept(
                        new AsyncCallback(AcceptCallback),
                        listener);
                    allDone.WaitOne();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        public static void AcceptCallback(IAsyncResult ar)
        {
            logHandler("[Connections] Got a connection...");

            // Signal the main thread to continue.
            allDone.Set();

            // Get the socket that handles the client request.
            Socket listener = (Socket)ar.AsyncState;
            Socket handler = listener.EndAccept(ar);

            // Create the state object.
            var state = new StateObject();
            state.workSocket = handler;
            handler.BeginReceive(state.buffer, 0, state.buffer.Length, 0, new AsyncCallback(ReadCallback), state);
        }

        public static async void ReadCallback(IAsyncResult ar)
        {
            logHandler("[Connections] Reading client message...");
            // Retrieve the state object and the handler socket
            // from the asynchronous state object.
            var state = (StateObject) ar.AsyncState;
            Socket handler = state.workSocket;

            // Read data from the client socket. 
            int bytesRead = handler.EndReceive(ar);
            state.bytesRead += bytesRead;

            if (bytesRead == 0 && state.bytesRead == 0)
            {
                // Client doesn't want to send anything, maybe its waiting for another server reply?
                state.bytesRead = 0;
                state.buffer = new byte[1024 * 1024];
                state.esoSocket.BeginReceive(state.buffer, 0, state.buffer.Length, 0, new AsyncCallback(ReadESOCallback), state);
                return;
            }
            
            try
            {
                byte[] bytesReadSoFar = new byte[state.bytesRead];
                Buffer.BlockCopy(state.buffer, 0, bytesReadSoFar, 0, bytesReadSoFar.Length);

                flowAnalyzer.ProcessClientZonePacket(bytesReadSoFar);
            }
            catch (ESOSniffer.ZonePacket.NotEnoughBytesException)
            {
                handler.BeginReceive(state.buffer, state.bytesRead, state.buffer.Length - state.bytesRead, 0, new AsyncCallback(ReadCallback), state);
                return;
            }

            Array.Resize(ref state.buffer, bytesRead);
            //File.WriteAllBytes("" + requestGotCount++ + "_client", state.buffer);
            var packet = (ZonePacket)flowAnalyzer.ClientMessages.Last();
            File.WriteAllBytes("" + packet.SequenceID.ToString("X") + "_client", packet.Data);
            File.WriteAllBytes("" + packet.SequenceID.ToString("X") + "_client_raw", state.buffer);
            // Foward message to message1.aom.eso.com server
            if (state.esoSocket == null)
            {
                logHandler("[Connections] Connecting to message1.aom.eso.com...");
                IPHostEntry ipHostInfo = await Dns.GetHostEntryAsync("message1.aom.eso.com");//message1.aom.eso.com
                IPAddress ipAddress = ipHostInfo.AddressList[0];//0
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 28805);

                // Create a TCP/IP socket.
                Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                state.esoSocket = client;
                // Connect to the remote endpoint.
                client.BeginConnect(remoteEP, new AsyncCallback(ConnectCallback), state);
            }
            else
            {
                state.esoSocket.BeginSend(state.buffer, 0, state.buffer.Length, SocketFlags.None,
                    new AsyncCallback(SendESOCallback), state);
            }
        }

        private static void ConnectCallback(IAsyncResult ar)
        {
            var state = (StateObject)ar.AsyncState;
            Socket client = state.esoSocket;

            // Complete the connection.
            logHandler("[Connections] Fowarding message...");
            client.EndConnect(ar);

            client.BeginSend(state.buffer, 0, state.buffer.Length, SocketFlags.None,
                new AsyncCallback(SendESOCallback), state);
        }

        private static void SendESOCallback(IAsyncResult ar)
        {
            var state = (StateObject)ar.AsyncState;
            Socket eso = state.esoSocket;

            int bytesSent = eso.EndSend(ar);
            logHandler("[Connections] Done fowarding message to eso... (" + bytesSent + "/" + state.buffer.Length + ")");
            logHandler("[Connections] Waiting for ESO reply...");

            state.bytesRead = 0;
            state.buffer = new byte[1024 * 1024];
            eso.BeginReceive(state.buffer, 0, state.buffer.Length, 0, new AsyncCallback(ReadESOCallback), state);
        }

        public static void ReadESOCallback(IAsyncResult ar)
        {
            logHandler("[Connections] Reading ESO reply...");
            // Retrieve the state object and the handler socket
            // from the asynchronous state object.
            var state = (StateObject)ar.AsyncState;
            Socket handler = state.esoSocket;

            // Read data from the client socket. 
            int bytesRead = handler.EndReceive(ar);
            state.bytesRead += bytesRead;

            try
            {
                byte[] bytesReadSoFar = new byte[state.bytesRead];
                Buffer.BlockCopy(state.buffer, 0, bytesReadSoFar, 0, bytesReadSoFar.Length);

                flowAnalyzer.ProcessServerZonePacket(bytesReadSoFar);
            }
            catch (ESOSniffer.ZonePacket.NotEnoughBytesException)
            {
                handler.BeginReceive(state.buffer, state.bytesRead, state.buffer.Length - state.bytesRead, 0, new AsyncCallback(ReadESOCallback), state);
                return;
            }

            Array.Resize(ref state.buffer, state.bytesRead);
            if (requestSentCount++ == 0)
            {
                // ignore
            }
            else
            {
                var packet = (ZonePacket)flowAnalyzer.ServerMessages.Last();
                //File.WriteAllBytes("" + packet.SequenceID.ToString("X") + "_server", packet.Data);
                //File.WriteAllBytes("" + packet.SequenceID.ToString("X") + "_server_raw", state.buffer);
            }

            // Foward message to client
            logHandler("[Connections] Fowarding message to client");

            try
            {
                state.workSocket.BeginSend(state.buffer, 0, state.buffer.Length, SocketFlags.None,
                    new AsyncCallback(SendCallback), state);
            }
            catch
            {
                logHandler("[Connections] Client closed connection.");
                flowAnalyzer.state = new State();
            }
        }

        private static void SendCallback(IAsyncResult ar)
        {
            var state = (StateObject)ar.AsyncState;
            Socket client = state.workSocket;

            int bytesSent = client.EndSend(ar);
            logHandler("[Connections] Done fowarding message to client... (" + bytesSent + "/" + state.buffer.Length + ")");

            Array.Resize(ref state.buffer, bytesSent);

            // listen to client again
            state.bytesRead = 0;
            state.buffer = new byte[1024 * 8];
            client.BeginReceive(state.buffer, 0, state.buffer.Length, 0, new AsyncCallback(ReadCallback), state);
        }
    }
}
