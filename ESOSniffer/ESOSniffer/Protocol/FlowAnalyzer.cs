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
using ESOSniffer.Protocol;
using System.IO;

namespace ESOSniffer.Protocol
{
    /// <summary>
    /// Analyze what Client and Server are communicating
    /// </summary>
    public class FlowAnalyzer
    {
        public List<object> ServerMessages = new List<object>();

        public List<object> ClientMessages = new List<object>();

        public State state = new State();

        public static ESOSniffer.Connections.LogHandler logHandler;

        private bool hasServerAccessBeenGranted = false;

        private MessageStruct.IMessageStruct ProcessMessage(Message Message)
        {
            logHandler("[FlowAnalyzer][Message] Type found: " + ((Message.TYPE_ID)Message.TypeID));

            switch (Message.TypeID)
            {
                case (Int32)Message.TYPE_ID.FIRST_SECURE_MESSAGE:
                    var firstSecureMessage = (MessageStruct.FirstSecureMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][FirstSecureMessage]"
                                + " Unkown_1: " + (firstSecureMessage.Unkown_1).ToString("X"));
                    return firstSecureMessage;
                case (Int32)Message.TYPE_ID.FIRST_SECURE_MESSAGE_SERVER:
                    var firstSecureMessageServer = (MessageStruct.FirstSecureMessageServer)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][FirstSecureMessageServer]");
                    return firstSecureMessageServer;
                case (Int32)Message.TYPE_ID.GENERATE_SECURITY_CONTEXT:
                    var generateSecurityContext = (MessageStruct.GenerateSecurityContext)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][GenerateSecurityContext]"
                                + " UserID[" + generateSecurityContext.UserID + "] "
                                + " UserEncryptedPassword["
                                        + BitConverter.ToString(generateSecurityContext.UserEncryptedPassword).Replace("-", "") + "]");
                    return generateSecurityContext;
                case (Int32)Message.TYPE_ID.SECURITY_CONTEXT_SERVER_MSG:
                    var securityContextServer = (MessageStruct.SecurityContextServer)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][SecurityContextServer]"
                                + " Unkown_Key: " + (securityContextServer.Unkown_Key).ToString("X"));
                    return securityContextServer;
                case (Int32)Message.TYPE_ID.AUTHENTICATE_MSG:
                    var authenticate = (MessageStruct.AuthenticateMessage)MessageStruct.ParseMessageData(Message);

                    logHandler("[FlowAnalyzer][Message][SecurityContextServer]"
                                + " Unkown_2: " + BitConverter.ToString(authenticate.Unkown_2).Replace("-", ""));
                    return authenticate;
                case (Int32)Message.TYPE_ID.SERVER_ACCESS_DENIED:
                    var serverAccessDenied = (MessageStruct.ServerAccessDenied)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][ServerAccessDenied] Reason: " + serverAccessDenied.Reason);
                    return serverAccessDenied;
                case (Int32)Message.TYPE_ID.SERVER_ACCESS_GRANTED:
                    hasServerAccessBeenGranted = true;
                    var serverAccessGranted = (MessageStruct.ServerAccessGranted)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][serverAccessGranted] Username: " + serverAccessGranted.Username);
                    logHandler("[FlowAnalyzer][Message][serverAccessGranted] UserID: " + serverAccessGranted.UserID);
                    return serverAccessGranted;
                case (Int32)Message.TYPE_ID.CONNECT_MSG:
                    var connectMessage = (MessageStruct.ConnectMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][ConnectMessage] Protocol: " + connectMessage.ProtocolSignature);
                    return connectMessage;
                case (Int32)Message.TYPE_ID.CONNECT_ACK_MSG:
                    var connectAckMessage = (MessageStruct.ConnectAckMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][ConnectAckMessage] Protocol: " + connectAckMessage.ConfigurationText);
                    return connectAckMessage;
                case (Int32)Message.TYPE_ID.DATA_MSG:
                    var dataMessage = (MessageStruct.DataMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][DataMessage] Username: " + dataMessage.Username);
                    logHandler("[FlowAnalyzer][Message][DataMessage]"
                             + " DataLength[" + dataMessage.DataLength + "] DataString: " + dataMessage.DataString);
                    return dataMessage;
                case (Int32)Message.TYPE_ID.DATA_ACK_MSG:
                    return null;
                case (Int32)Message.TYPE_ID.DISCONNECT_MSG:
                    return null;
                case (Int32)Message.TYPE_ID.STATE_MSG:
                    var stateMessage = (MessageStruct.StateMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][StateMessage]"
                                + " AppID[" + (MessageStruct.AppID)stateMessage.getAppID() + "] "
                                + " State: " + stateMessage.getState());
                    return stateMessage;
                case (Int32)Message.TYPE_ID.USER_MSG:
                    var userMessage = (MessageStruct.UserMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][UserMessage]"
                                + " AppID[" + (MessageStruct.AppID)userMessage.getAppID() + "]"
                                + " State[" + userMessage.getState() + "]"
                                + " Username: " + userMessage.Username);
                    return userMessage;
                case (Int32)Message.TYPE_ID.ERROR_MSG:
                    var errorMessage = (MessageStruct.ErrorMessage)MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][ErrorMessage] Message: " + errorMessage.Message);
                    return errorMessage;
                case (Int32)Message.TYPE_ID.WATCH_MSG:
                    var watchMessage = (MessageStruct.WatchMessage) MessageStruct.ParseMessageData(Message);
                    logHandler("[FlowAnalyzer][Message][WatchMessage] Username: " + watchMessage.Username);
                    return watchMessage;
            }
            return null;
        }

        public void ProcessClientZonePacket(byte[] rawData)
        {
            logHandler("[FlowAnalyzer] Processing Client Message...");

            byte[] data = new byte[rawData.Length];
            Buffer.BlockCopy(rawData, 0, data, 0, rawData.Length);

            ZonePacket packet;
            try
            {
                packet = ZonePacket.Parse(ref data, state.Client.SecureKey);
            }
            catch (ESOSniffer.ZonePacket.CRCMismatchException e)
            {
                packet = e.ParsedPacket;
                logHandler("[FlowAnalyzer] Warning - CRCMismatchException (" + packet.CRC.ToString("X") + " != " + e.ComputedCRC.ToString("X") + ").");
            }

            ClientMessages.Add(packet);
            if (packet.Signature != ZonePacket.ZONE_SIGNATURE)
            {
                logHandler("[FlowAnalyzer] Error - invalid signature (" + packet.Signature + ").");
            }
            else if (state.Client.Connecting)
            {
                state.Client.Connecting = false;
                logHandler("[FlowAnalyzer] Client - Initial handshake.");
            }
            else
            {
                Message message = Message.Parse(packet);

                logHandler("[FlowAnalyzer]"
                        + " Size[" + packet.Size + "]"
                        + " SequenceID[" + packet.SequenceID.ToString("X") + "]"
                        + " CRC[" + packet.CRC.ToString("X") + "]");
                logHandler("[FlowAnalyzer]"
                        + " Message ID[" + message.TypeID + "]"
                        + " Size[" + message.Size + "]");

                try
                {
                    File.WriteAllBytes("" + packet.SequenceID.ToString("X") + "_client", packet.Data);
                }
                catch
                {
                }
                if (hasServerAccessBeenGranted && message.TypeID == (Int32)Message.TYPE_ID.SERVER_ACCESS_GRANTED)
                {
                    message.TypeID += 2000;
                }
                ProcessMessage(message);

                // Check if it has something else to process
                if (!state.Client.Connecting && data.Length > 0)
                {
                    ProcessClientZonePacket(data);
                }
            }
        }

        public void ProcessServerZonePacket(byte[] rawData)
        {
            logHandler("[FlowAnalyzer] Processing Server Message...");

            byte[] data = new byte[rawData.Length];
            Buffer.BlockCopy(rawData, 0, data, 0, rawData.Length);

            if (state.Server.Connecting)
            {
                state.Server.Connecting = false;
                var packet = FirstZonePacket.Parse(data);
                ServerMessages.Add(packet);

                state.Server.SecureKey = packet.SecureKey;
                state.Client.SecureKey = packet.SecureKey;
                state.Server.SequenceID = packet.SequenceID;
                state.Client.SequenceID = packet.SequenceID;
                logHandler("[FlowAnalyzer] Server - Initial handshake complete. "
                        + "SecureKey[" + packet.SecureKey.ToString("X") + "]"
                        + " SequenceID[" + packet.SequenceID.ToString("X") + "]");
            }
            else
            {
                ZonePacket packet;
                try
                {
                    packet = ZonePacket.Parse(ref data, state.Server.SecureKey);
                }
                catch (ESOSniffer.ZonePacket.CRCMismatchException e)
                {
                    packet = e.ParsedPacket;
                    logHandler("[FlowAnalyzer] Warning - CRCMismatchException (" + packet.CRC.ToString("X") + " != " + e.ComputedCRC.ToString("X") + ").");
                }
                ServerMessages.Add(packet);

                if (packet.Signature != ZonePacket.ZONE_SIGNATURE)
                {
                    logHandler("[FlowAnalyzer] Error - invalid signature (" + packet.Signature + ").");
                }
                try
                {
                    File.WriteAllBytes("" + packet.SequenceID.ToString("X") + "_server", packet.Data);
                }
                catch
                {
                }
                Message message = Message.Parse(packet);

                logHandler("[FlowAnalyzer]"
                        + " Size[" + packet.Size + "]"
                        + " SequenceID[" + packet.SequenceID.ToString("X") + "]"
                        + " CRC[" + packet.CRC.ToString("X") + "]");
                logHandler("[FlowAnalyzer]"
                        + " Message ID[" + message.TypeID +"]"
                        + " Size[" + message.Size + "]");
                var messageProcessed = ProcessMessage(message);
                if (messageProcessed is MessageStruct.UserMessage)
                {
                }

                if (!state.Server.Connecting && data.Length > 0)
                {
                    ProcessServerZonePacket(data);
                }
            }
        }
    }
}
