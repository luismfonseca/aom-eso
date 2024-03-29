﻿/**
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
using ESO_Zone_Server.Protocol.Packet;
using ESO_Zone_Server.Protocol.Messages;
using System.Net;
using System.IO;

namespace ESO_Zone_Server.Protocol
{
    public static class Zone
    {
        public const int MSG_PORT = 28801;
        public const int LOBBY_PORT = 28805;
        public const int LOBBIES_COUNT = 19;

        public static List<ZoneClient> OnlineClients = new List<ZoneClient>();

        public static List<ZoneLobby> ZoneLobbies = new List<ZoneLobby>();

        public static void InitiateZoneLobbies()
        {
            for (int i = 0; i < LOBBIES_COUNT; i++)
            {
                ZoneLobbies.Add(new ZoneLobby());
            }
        }

        public static ZoneLobby GetZoneLobby(int Port)
        {
            return ZoneLobbies[Port - LOBBY_PORT];
        }

        private static string getUsernameByID(int UserID)
        {
            HttpWebRequest webRequest = (HttpWebRequest)HttpWebRequest.Create("http://paginas.fe.up.pt/~ei10139/aomsvr/getUsernameByID.php?id=" + UserID);
            using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
            using (var reader = new StreamReader(webResponse.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }

        public static List<IZonePacket> Process(ZoneClient zoneClient, byte[] data)
        {
            var packetsToSend = new List<IZonePacket>();
            ZonePacket packet;
            try
            {
                packet = ZonePacket.Parse(ref data, zoneClient.SecureKey);
            }
            catch (Packet.ZonePacket.CRCMismatchException ex)
            {
                packet = ex.ParsedPacket;
                Log.Warning("Zone", "CRC Mismatch. Expected[" + ex.ComputedCRC + "] Got[" + packet.CRC + "]");
                // This should not happen... but we shall ignore
            }
            if (packet.Signature != ZonePacket.ZONE_SIGNATURE)
            {
                Log.Debug("Zone", "Wrong signature. "
                    + "Expected[" + ZonePacket.ZONE_SIGNATURE
                    + "] Got[" + packet.Signature + "]");
            }
            switch (zoneClient.CurrentProtocolState)
            {
                case ZoneClient.UserProtocolState.Connecting:
                    {
                        Random random = new Random();
                        byte key = (byte)random.Next(byte.MaxValue);
                        UInt32 secureKey = BitConverter.ToUInt32(new byte[] { key, key, key, key }, 0);
                        UInt32 sequenceID = BitConverter.ToUInt32(
                                new byte[]
                        {
                            (byte)random.Next(byte.MaxValue),
                            (byte)random.Next(byte.MaxValue),
                            (byte)random.Next(byte.MaxValue),
                            (byte)random.Next(byte.MaxValue)
                        }, 0);

                        zoneClient.CurrentProtocolState = ZoneClient.UserProtocolState.ExchangingFirstSecureMessage;

                        secureKey = 2694881440;
                        sequenceID = 2693930841;

                        zoneClient.SecureKey = (Int32)secureKey;
                        zoneClient.SequenceID = sequenceID;
                        var unionType = zoneClient.IsOnLobby ?
                                FirstZonePacket.UnionTypes.ZCHAT_FIRST_MSG : FirstZonePacket.UnionTypes.ZCONN_FIRST_MSG;
                        return new List<IZonePacket>()
                        {
                            new FirstZonePacket(secureKey, sequenceID, unionType)
                        };
                    }
                case ZoneClient.UserProtocolState.ExchangingFirstSecureMessage:
                    {
                        zoneClient.CurrentProtocolState = ZoneClient.UserProtocolState.GeneratingSecurityContext;
                        var messageClient = Message.Parse(packet);
                        var messageServer = new Messages.Messages.FirstSecureMessageServer();

                        return new List<IZonePacket>()
                        {
                            ZonePacket.FromMessage(messageServer, zoneClient)
                        };
                    }
                case ZoneClient.UserProtocolState.GeneratingSecurityContext:
                    {
                        zoneClient.CurrentProtocolState = ZoneClient.UserProtocolState.Authenticating;
                        var messageClient = Message.Parse(packet);
                        int userID = ((Messages.Messages.GenerateSecurityContext)messageClient).UserID;
                        Log.Inform("ZoneService", "Client ID[" + userID + "]");
                        zoneClient.UserID = userID;

                        // TODO: Resolve username here...
                        zoneClient.Username = Zone.getUsernameByID(userID);
                        if (string.IsNullOrEmpty(zoneClient.Username)) // what do to ?
                        {
                            zoneClient.Username = "DOA_invent00r";
                        }
                        zoneClient.Username += '\0';

                        var messageServer = new Messages.Messages.SecurityContextServer();
                        return new List<IZonePacket>()
                        {
                            ZonePacket.FromMessage(messageServer, zoneClient)
                        };
                    }
                case ZoneClient.UserProtocolState.Authenticating:
                    {
                        zoneClient.CurrentProtocolState = ZoneClient.UserProtocolState.ConnectingProtocol;
                        var messageClient = Message.Parse(packet);
                        Log.Inform("ZoneService", "Access granted to client");

                        var messageServer = new Messages.Messages.ServerAccessGranted(zoneClient.UserID, zoneClient.Username);
                        return new List<IZonePacket>()
                        {
                            ZonePacket.FromMessage(messageServer, zoneClient)
                        };
                    }
                case ZoneClient.UserProtocolState.ConnectingProtocol:
                    {
                        zoneClient.CurrentProtocolState = ZoneClient.UserProtocolState.Online;
                        var messageClient = Message.Parse(packet);

                        if (messageClient is Messages.Messages.RoomConnectMessage)
                        {
                            zoneClient.UserLobbyID = zoneClient.Lobby.GetNextAvailableUserLobbyID();
                            var roomAccessedMessage = new Messages.Messages.RoomAccessedMessage(zoneClient.UserLobbyID);

                            zoneClient.Lobby.Users.Add(zoneClient);

                            return new List<IZonePacket>()
                            {
                                ZonePacket.FromMessage(roomAccessedMessage, zoneClient),
                            };
                        }
                        else
                        {
                            Zone.OnlineClients.Add(zoneClient);
                            var messageServer = new Messages.Messages.ConnectAckMessage(zoneClient.Username);
                            var welcomeServerMessage =
                                    new Messages.Messages.DataMessageStringServer(
                                            "Server",
                                            "Welcome online! Please send your feedback using /feedback {insert suggestion here} on the chat.");
                            return new List<IZonePacket>()
                            {
                                ZonePacket.FromMessage(messageServer, zoneClient),
                                ZonePacket.FromMessage(welcomeServerMessage, zoneClient)
                            };
                        }
                    }
                case ZoneClient.UserProtocolState.Online:
                    {
                        var messageClient = Message.Parse(packet, zoneClient.IsOnLobby);

                        if (messageClient is Messages.Messages.TalkMessage)
                        {
                            var talkMessageClient = (messageClient as Messages.Messages.TalkMessage);
                            zoneClient.Lobby.Messages.Add(Tuple.Create(zoneClient.UserLobbyID, talkMessageClient.Message));
                        }
                        else if (messageClient is Messages.Messages.WatchMessage)
                        {
                            var watchMessage = messageClient as Messages.Messages.WatchMessage;
                            zoneClient.WatchList.Add(watchMessage.Username);
                            
                            var watchAckMessage = new Messages.Messages.WatchAckMessage(watchMessage.Username);
                            packetsToSend.Add(
                                    ZonePacket.FromMessage(watchAckMessage, zoneClient));

                            // TODO: Replace with proper awnser
                            var otherClient = Zone.OnlineClients.SingleOrDefault(client =>
                                    string.Equals(client.Username, watchMessage.Username, StringComparison.InvariantCultureIgnoreCase));
                            if (otherClient != null)
                            {
                                var userMessage = new Messages.Messages.UserMessage(
                                        otherClient.Username, otherClient.CurrentAppID, otherClient.CurrentUserState);

                                packetsToSend.Add(
                                        ZonePacket.FromMessage(userMessage, zoneClient));
                            }
                            // TODO: else

                        }
                        else if (messageClient is Messages.Messages.StateMessage)
                        {
                            var stateMessage = messageClient as Messages.Messages.StateMessage;
                            Zone.SetCurrentUserStateAndAppID(zoneClient, stateMessage.GetUserState(), stateMessage.GetAppID(), packetsToSend);
                        }
                        else if (messageClient is Messages.Messages.DataMessageClient)
                        {
                            var dataMessage = messageClient as Messages.Messages.DataMessageClient;

                            var dataAckMessage = new Messages.Messages.DataMessageAck(zoneClient.Username);
                            packetsToSend.Add(
                                    ZonePacket.FromMessage(dataAckMessage, zoneClient));

                            switch (dataMessage.Type)
                            {
                                case Messages.Messages.DataMessageType.String:
                                    {
                                        Log.Inform("Zone", "User [" + zoneClient.Username.TrimEnd('\0') + "]:"
                                                + " ToUser[" + dataMessage.Username.TrimEnd('\0') + "]"
                                                + " Message[" + dataMessage.DataString.TrimEnd('\0') + "]");

                                        if (string.Equals("feedback", dataMessage.Username, StringComparison.InvariantCultureIgnoreCase))
                                        {
                                            string messageFormat = "{0}: {1}\n";
                                            string messageFormatted = string.Format(messageFormat, zoneClient.Username.TrimEnd('\0'), dataMessage.DataString.TrimEnd('\0'));
                                            File.AppendAllText("Feedback.txt", messageFormatted, Encoding.BigEndianUnicode);
                                            break;
                                        }
                                        var otherClient = Zone.OnlineClients.SingleOrDefault(client =>
                                                string.Equals(client.Username, dataMessage.Username, StringComparison.InvariantCultureIgnoreCase));
                                        if (otherClient != null)
                                        {
                                            var stringMessage = new Messages.Messages.DataMessageStringServer(
                                                    zoneClient.Username,
                                                    dataMessage.DataString);

                                            otherClient.packetsToBeSent.Add(ZonePacket.FromMessage(stringMessage, otherClient));
                                        }
                                        else
                                        {
                                            // TODO
                                        }

                                        break;
                                    }
                                //case Messages.Messages.DataMessageType.Invitation:
                                //case Messages.Messages.DataMessageType.InvitationResponse:
                                //case Messages.Messages.DataMessageType.InvitationClientToJoinGame:
                                //case Messages.Messages.DataMessageType.InvitationTimeout: // not sure if needed
                                //case Messages.Messages.DataMessageType.InvitationTimeout2:
                                //case Messages.Messages.DataMessageType.ClientToJoinGame:
                                //case Messages.Messages.DataMessageType.ClientToJoinGameResponse:
                                default:
                                    {
                                        var otherClient = Zone.OnlineClients.SingleOrDefault(client =>
                                                string.Equals(client.Username, dataMessage.Username, StringComparison.InvariantCultureIgnoreCase));
                                        if (otherClient != null)
                                        {
                                            var dataMessageServer = new Messages.Messages.DataMessageServer(
                                                    zoneClient.Username,
                                                    dataMessage.Data);

                                            otherClient.packetsToBeSent.Add(ZonePacket.FromMessage(dataMessageServer, otherClient));
                                        }
                                        else
                                        {
                                            Log.Warning("Zone", "User [" + zoneClient.Username.TrimEnd('\0') + "]:"
                                                    + " ToUser[" + dataMessage.Username.TrimEnd('\0') + "]"
                                                    + " UnkownMessage");
                                            // TODO
                                        }
                                        break;
                                    }
                            }
                        }
                        break;
                    }
            }

            // Check if there are more packets to process
            if (data.Length > 0)
            {
                packetsToSend.AddRange(Process(zoneClient, data));
            }
            return packetsToSend;
        }

        public static void SetCurrentUserStateAndAppID(
            ZoneClient zoneClient, ZoneClient.UserState userState, ZoneClient.AppID appID, List<IZonePacket> packets = null)
        {
            zoneClient.CurrentAppID = ((Int32)appID == 16) ? ZoneClient.AppID.AoT : ZoneClient.AppID.AoM;
            zoneClient.CurrentUserState = userState;

            Log.Inform("Zone", "User [" + zoneClient.Username.TrimEnd('\0') + "]:"
                    + " AppID[" + zoneClient.CurrentAppID + "]"
                    + " UserState[" + zoneClient.CurrentUserState + "]");

            var stateAckMessage = new Messages.Messages.StateAckMessage();
            if (packets == null)
            {
                zoneClient.packetsToBeSent.Add(
                        ZonePacket.FromMessage(stateAckMessage, zoneClient));
            }
            else
            {
                packets.Add(
                        ZonePacket.FromMessage(stateAckMessage, zoneClient));
            }

            var userMessage = new Messages.Messages.UserMessage(zoneClient.Username, zoneClient.CurrentAppID, zoneClient.CurrentUserState);
            Zone.OnlineClients
                .Where(client => string.Equals(client.Username, zoneClient.Username, StringComparison.OrdinalIgnoreCase) == false
                                 && client.WatchList.Contains(zoneClient.Username.TrimEnd('\0'), StringComparer.OrdinalIgnoreCase))
                    .ForEach(_ => _.packetsToBeSent.Add(
                            ZonePacket.FromMessage(userMessage, _)));
        }

        public static void ForEach<T>(this IEnumerable<T> source, Action<T> action)
        {
            foreach (T element in source)
            {
                action(element);
            }
        }

        public static void ClientWentOffline(ASyncClient client)
        {
            if (client.zoneClient.IsOnLobby)
            {
                client.zoneClient.Lobby.Users.Remove(client.zoneClient);
            }
            else if (client.zoneClient.CurrentProtocolState != ZoneClient.UserProtocolState.Online)
            {
                return;
            }
            else
            {
                Zone.SetCurrentUserStateAndAppID(client.zoneClient, ZoneClient.UserState.Offline, ZoneClient.AppID.Offline);
                Zone.OnlineClients.RemoveAll(_ => _.Username == client.zoneClient.Username);
            }
        }
    }
}
