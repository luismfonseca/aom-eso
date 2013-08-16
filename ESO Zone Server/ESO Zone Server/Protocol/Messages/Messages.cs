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
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using zlib;

namespace ESO_Zone_Server.Protocol.Messages
{
    public static class Messages
    {
        public enum SIGNATURE
        {
            FIRST_SECURE_MESSAGE = 1,
            FIRST_SECURE_MESSAGE_SERVER = 2,
            GENERATE_SECURITY_CONTEXT = 5,
            SECURITY_CONTEXT_SERVER_MSG = 4,
            AUTHENTICATE_MSG = 3,
            SERVER_ACCESS_DENIED = 6,
            SERVER_ACCESS_GRANTED = 7,
            CONNECT_MSG = 4097,
            CONNECT_ACK_MSG = 4098,
            DISCONNECT_MSG = 4099,
            //DISCONNECT_ASK_MSG = 4100, // Most likely it doesn't exist
            STATE_MSG = 4101, // SET_STATUS
            STATE_ACK_MSG = 4102,
            WATCH_MSG = 4105,
            WATCH_ACK_MSG = 4106,
            DATA_MSG = 4111,
            DATA_ACK_MSG = 4112,
            USER_MSG = 8192,
            ERROR_MSG = 8193,
            PING_MSG = -2147483648
        }

        public enum SIGNATURE_CHAT
        {
            ROOM_CONNECT = 0,
            ROOM_ACCESSED = 11,
            ROOM_INFO = 1,
            TALK = 7,
            TALK_RESPONSE = 8,
            //? TALK_ID = 12,
            TALK_RESPONSE_ID = 13,
            ENTER = 2,
            LEAVE = 3,
            DISCONNECT = 12,
            PING_MSG = -2147483648
        }

        public static List<MessageClient> getAllClientMessages()
        {
            return (from assembly in AppDomain.CurrentDomain.GetAssemblies()
                    from type in assembly.GetTypes()
                    where typeof(MessageClient).IsAssignableFrom(type) && typeof(MessageClient) != type
                    select (MessageClient)Activator.CreateInstance(type)).ToList<MessageClient>();
        }

        public class FirstSecureMessage : MessageClient
        {
            /// <summary>
            /// Always 2054382947, or 'cesz' which is zsec backwards. Short for ZSecurityMessage
            /// </summary>
            public Int32 ID;

            /// <summary>
            /// Always 1 (gameID?)
            /// </summary>
            public Int32 Unknown_0;

            /// <summary>
            /// I've seen B0E93372, B0E9F06B, or all 0s
            /// </summary>
            public Int32 Unknown_1;

            public override Int32 GetTypeID()
            {
                return (Int32) Messages.SIGNATURE.FIRST_SECURE_MESSAGE;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedFirstSecureMessage = new FirstSecureMessage();
                parsedFirstSecureMessage.ID = BitConverter.ToInt32(Data, 0);
                parsedFirstSecureMessage.Unknown_0 = BitConverter.ToInt32(Data, 4);
                //parsedFirstSecureMessage.Unknown_1 = BitConverter.ToInt32(Data, 8);

                return parsedFirstSecureMessage;
            }
        }

        public class FirstSecureMessageServer : MessageServer
        {
            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unknown_0 = 1;

            /// <summary>
            /// Always "ZWebAuth"
            /// </summary>
            public string ZWebAuthSignature = "ZWebAuth";

            /// <summary>
            /// Some values, not sure if they are important
            /// </summary>
            public byte[] Unknown_1 = new byte[44];

            public override Int32 GetTypeID()
            {
                return (Int32) Messages.SIGNATURE.FIRST_SECURE_MESSAGE_SERVER;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 8 + 44), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);
                memoryStream.Write(Encoding.ASCII.GetBytes(ZWebAuthSignature), 0, 8);
                memoryStream.Write(Unknown_1, 0, Unknown_1.Length);
                return memoryStream.ToArray();
            }
        }

        public class GenerateSecurityContext : MessageClient
        {
            /// <summary>
            /// 'cesz', meaning zSecurityRequest
            /// </summary>
            public string ZSecurityRequestSignature;

            /// <summary>
            /// Always 1 (maybe it's AppID?)
            /// </summary>
            public Int32 Unknown_0;

            /// <summary>
            /// Always 2054644014. Or ".awz", "zwa." backwards. Might mean ZWatchMessage
            /// </summary>
            public string ZWatchSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unknown_1;

            /// <summary>
            /// User ID as given by AccountService.asmx
            /// </summary>
            public Int32 UserID;

            /// <summary>
            /// Always 'ZONE'
            /// </summary>
            public string ZONESignature;

            /// <summary>
            /// User Encrypted Password. The algorithm is still unknow, I think it uses md5 with a mask and a few extra tricks.
            /// </summary>
            public byte[] UserEncryptedPassword;

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.GENERATE_SECURITY_CONTEXT;
            }

            // this message also has pw encrypted
            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedMessage = new GenerateSecurityContext();
                parsedMessage.ZSecurityRequestSignature = System.Text.Encoding.ASCII.GetString(Data, 0, 4);
                parsedMessage.Unknown_0 = BitConverter.ToInt32(Data, 4);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 8, 4);
                parsedMessage.Unknown_1 = BitConverter.ToInt32(Data, 12);
                parsedMessage.UserID = BitConverter.ToInt32(Data, 16);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 20, 4);
                parsedMessage.UserEncryptedPassword = new byte[32];
                Buffer.BlockCopy(Data, 24, parsedMessage.UserEncryptedPassword, 0, parsedMessage.UserEncryptedPassword.Length);

                return parsedMessage;
            }
        }

        public class SecurityContextServer : MessageServer
        {
            /// <summary>
            /// Always 1 (maybe it's AppID?)
            /// </summary>
            public Int32 Unknown_0 = 1;

            /// <summary>
            /// "ZWebAuth" or 0x5A5765624175746800
            /// </summary>
            public string ID = "ZWebAuth\0";

            /// <summary>
            /// Fixed size and fixed message.
            /// When xor'ed with 0x78, we get 4E6F5A2B000000E3783796205F09CE012000002300000000000000000001009A0800005741544348
            /// Starts with "NoZ+" or "+ZoN" backwards.
            /// </summary>
            public byte[] Unknown_1 = new byte[]
            {
                0x36, 0x17, 0x22, 0x53, 0x78, 0x78, 0x78, 0x9B, 0x00, 0x4F, 0xEE, 0x58, 0x27, 0x71, 0xB6, 0x79, 0x58, 0x78, 0x78, 0x5B,
                0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x79, 0x78, 0xE2, 0x70, 0x78, 0x78, 0x2F, 0x39, 0x2C, 0x3B, 0x30
            };

            /// <summary>
            /// Always 2054644014. Or ".awz", "zwa." backwards. Might mean ZWatchMessage
            /// </summary>
            public string ZWatchSignature = ".awz";

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unknown_2 = 1;

            /// <summary>
            /// Random key sent by server. Maybe used to encrypt Passkey?
            /// </summary>
            public Int64 Unknown_Key = 0;

            /// <summary>
            /// Always 115, or 0x7300
            /// </summary>
            public Int16 Unknown_3 = 115;

            /// <summary>
            /// Always 0
            /// </summary>
            public byte Unknown_4 = 0;

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.SECURITY_CONTEXT_SERVER_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 9 + 40 + 4 + 4 + 8 + 2 + 1), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(ID), 0, 9);
                memoryStream.Write(Unknown_1, 0, Unknown_1.Length);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(ZWatchSignature), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_2), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_Key), 0, 8);
                memoryStream.Write(BitConverter.GetBytes(Unknown_3), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unknown_4), 0, 1);

                return memoryStream.ToArray();
            }
        }

        public class AuthenticateMessage : MessageClient
        {
            /// <summary>
            /// 'cesz', meaning zSecurityRequest
            /// </summary>
            public string ZSecurityRequestSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unknown_0;

            /// <summary>
            /// Always 2054644014. Or ".awz", "zwa." backwards. Might mean ZWatchMessage
            /// </summary>
            public string ZWatchSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unknown_1;

            /// <summary>
            /// Not sure, but it's always 20 bytes long.
            /// </summary>
            public byte[] Unknown_2;
            
            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.AUTHENTICATE_MSG;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedMessage = new AuthenticateMessage();
                parsedMessage.ZSecurityRequestSignature = System.Text.Encoding.ASCII.GetString(Data, 0, 4);
                parsedMessage.Unknown_0 = BitConverter.ToInt32(Data, 4);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 8, 4);
                parsedMessage.Unknown_1 = BitConverter.ToInt32(Data, 12);
                parsedMessage.Unknown_2 = new byte[20];
                Buffer.BlockCopy(Data, 13, parsedMessage.Unknown_2, 0, parsedMessage.Unknown_2.Length);

                return parsedMessage;
            }
        }


        public class ServerAccessDenied : MessageServer
        {
            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unused_0 = 1;

            /// <summary>
            /// ID for reason being denied. (?)
            /// Wrong passkey or username: 16842756
            /// </summary>
            public Int32 Reason = 16842756;
            
            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.SERVER_ACCESS_DENIED;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 4), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Reason), 0, 4);

                return memoryStream.ToArray();
            }
        }

        public class ServerAccessGranted : MessageServer
        {
            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unused_0 = 1;

            /// <summary>
            /// Always "ZWebAuth", ending with \0
            /// </summary>
            public string ZWebAuthSignature = "ZWebAuth\0";

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_1 = 0;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_2 = 0;

            /// <summary>
            /// Username, Maximum length of 19
            /// </summary>
            public string UserName;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_3 = 0;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_4 = 0;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_5 = 0;

            /// <summary>
            /// "UserID=<xxxxxxx>" ending in \0
            /// </summary>
            public string UserID;

            public ServerAccessGranted(int userID, string userName)
            {
                this.UserName = userName.PadRight(20, '\0');
                this.UserID = "UserID=<" + userID + ">\0";
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.SERVER_ACCESS_GRANTED;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 9 + 4 + 4 + 20 + 4 + 4 + 4 + UserID.Length), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(ZWebAuthSignature), 0, 9);
                memoryStream.Write(BitConverter.GetBytes(Unused_1), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unused_2), 0, 4);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(UserName), 0, UserName.Length);
                memoryStream.Write(BitConverter.GetBytes(Unused_3), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unused_4), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unused_5), 0, 4);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(UserID), 0, UserID.Length);
                return memoryStream.ToArray();
            }
        }

        public class ConnectMessage : MessageClient
        {
            /// <summary>
            /// Always 0
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always 0x1000 or 65536. This is also used in ErrorMessage, ConnectMessage and ConnectRoomMessage
            /// </summary>
            public Int32 Unknown_0;

            /// <summary>
            /// Always "BLTP 1.0"
            /// </summary>
            public string ProtocolSignature;
            
            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.CONNECT_MSG;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedMessage = new ConnectMessage();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.Unknown_0 = BitConverter.ToInt32(Data, 4);
                parsedMessage.ProtocolSignature = Encoding.ASCII.GetString(Data, 8, 8);
                return parsedMessage;
            }
        }

        public class ConnectAckMessage : MessageServer
        {
            /// <summary>
            /// Always 0
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// Always 0x1000 or 65536. This is also used in ErrorMessage
            /// </summary>
            public Int32 Unknown_0 = 65536;

            /// <summary>
            /// Contains information about Username, MaxWatches, MaxFilters, MinChatVersion, ChatServer, ChatGuid and ChatData
            /// </summary>
            public string ConfigurationText = "user=<{0}>MaxWatches=<250>MaxFilters=<250>MinChatVersion=<6.1.500.1>ChatServer=<198292-FRONT3:28802>ChatGuid=<B5A42A1E-F44B-11D2-8B66-00C04F8EF2FF>ChatData=<ID=[DYNA]data=[game=[chat]dll=[ZoneCore.dll,ZoneClient.dll]datafile=[DynamicRes.dll,ChatRes.dll,CommonRes.dll]name=[Private]family=[Chat]]>\0";

            public ConnectAckMessage(string userName)
            {
                this.ConfigurationText = string.Format(ConfigurationText, userName);
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.CONNECT_ACK_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 4 + ConfigurationText.Length), 0, 4);
                
                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);
                memoryStream.Write(Encoding.ASCII.GetBytes(ConfigurationText), 0, ConfigurationText.Length);
                return memoryStream.ToArray();
            }
        }

        public class WatchMessage : MessageClient
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always 1 for WatchMessage
            /// </summary>
            public Int32 Unknown_0;

            /// <summary>
            /// Player's username.
            /// The last char is enconded differently: byteBeforeLast - byteLast.
            /// </summary>
            public String Username;

            /// <summary>
            /// This is a bug. I've fixed it in dll, it can be safely ingored otherwise.
            /// </summary>
            public byte Unknown_1;
            
            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.WATCH_MSG;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedWatchMessage = new WatchMessage();
                parsedWatchMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedWatchMessage.Unknown_0 = BitConverter.ToInt32(Data, 4);

                parsedWatchMessage.Username = System.Text.Encoding.ASCII.GetString(Data, 8, Data.Length - 1 - 8);

                parsedWatchMessage.Unknown_1 = Data.Last();
                return parsedWatchMessage;
            }
        }

        public class WatchAckMessage : MessageServer
        {
            /// <summary>
            /// Always 0
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unknown_0 = 1;

            /// <summary>
            /// Contains information about Username, MaxWatches, MaxFilters, MinChatVersion, ChatServer, ChatGuid and ChatData
            /// </summary>
            public string Username;

            public WatchAckMessage(string Username)
            {
                if (!Username.EndsWith("\0"))
                {
                    Username += "\0";
                }

                this.Username = Username;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.WATCH_ACK_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 4 + Username.Length), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(Username), 0, Username.Length);
                return memoryStream.ToArray();
            }
        }

        public class UserMessage : MessageServer
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// State & 0xFFFFFFEF and AppID & 0x10
            /// </summary>
            public Int32 UserStateAndAppID;

            /// <summary>
            /// Player's username.
            /// The last char is enconded differently: byteBeforeLast - byteLast.
            /// </summary>
            public string Username;

            public ZoneClient.AppID GetAppID()
            {
                if ((UserStateAndAppID & 0xFFFFFFEF) == 3)
                {
                    return ZoneClient.AppID.Offline;
                }
                return (UserStateAndAppID & 0x10) == 0 ? ZoneClient.AppID.AoM : ZoneClient.AppID.AoT;
            }

            public ZoneClient.UserState GetUserState()
            {
                return (ZoneClient.UserState)(UserStateAndAppID & 0xFFFFFFEF);
            }

            public UserMessage(string Username, ZoneClient.AppID AppID, ZoneClient.UserState UserState)
            {
                if (!Username.EndsWith("\0"))
                {
                    Username += "\0";
                }

                this.Username = Username;
                if (AppID == ZoneClient.AppID.Offline)
                {
                    UserStateAndAppID = (int)ZoneClient.AppID.Offline;
                }
                else
                {
                    UserStateAndAppID = (int)UserState;
                    if (AppID == ZoneClient.AppID.AoT)
                    {
                        UserStateAndAppID |= (int)16;
                    }
                }
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.USER_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 4 + Username.Length), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(UserStateAndAppID), 0, 4);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(Username), 0, Username.Length);
                return memoryStream.ToArray();
            }
        }

        public class StateMessage : MessageClient
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// State & 0xFFFFFFEF and AppID & 0x10
            /// </summary>
            public Int32 UserStateAndAppID;

            public ZoneClient.AppID GetAppID()
            {
                return (ZoneClient.AppID)(UserStateAndAppID & 0x10);
            }

            public ZoneClient.UserState GetUserState()
            {
                return (ZoneClient.UserState)(UserStateAndAppID & 0xFFFFFFEF);
            }
            
            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.STATE_MSG;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedStateMessage = new StateMessage();
                parsedStateMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedStateMessage.UserStateAndAppID = BitConverter.ToInt32(Data, 4);

                return parsedStateMessage;
            }
        }

        public class StateAckMessage : MessageServer
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// Unknown
            /// </summary>
            public Int32 Unknown_0 = 13;

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.STATE_ACK_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 4), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);
                return memoryStream.ToArray();
            }
        }

        public enum DataMessageType
        {
            String = 99,        // fake id
            ClientToJoinGame = 4,
            ClientToJoinGameResponse = 5,
            Invitation = 0,
            InvitationResponse = 1,
            InvitationClientToJoinGame = 2,
            InvitationTimeout = 7,
            InvitationTimeout2 = 3
        }

        public class DataMessageClient : MessageClient
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Data Length
            /// </summary>
            public Int16 DataLength;

            /// <summary>
            /// Username, variable length, ends with \0
            /// </summary>
            public string Username;

            /// <summary>
            /// Content of Data message
            /// </summary>
            public byte[] Data;

            /// <summary>
            /// DataMessage as a string
            /// </summary>
            public string DataString;

            /// <summary>
            /// Data messages can have a string or ips address used to connect players when in advanced mode
            /// </summary>
            public DataMessageType Type;

            /// <summary>
            /// The IP Address
            /// </summary>
            public IPAddress ipAddress;

            /// <summary>
            /// Alternative IP Address
            /// </summary>
            public IPAddress ipAddressSecondary;
            
            
            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.DATA_MSG;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedMessage = new DataMessageClient();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.DataLength = BitConverter.ToInt16(Data, 4);

                int offset = 6;
                while (Data[offset++] != 0);
                parsedMessage.Username = System.Text.Encoding.ASCII.GetString(Data, 6, offset - 6);

                parsedMessage.Data = new byte[parsedMessage.DataLength];
                Buffer.BlockCopy(Data, offset, parsedMessage.Data, 0, parsedMessage.Data.Length);
                parsedMessage.DataString = System.Text.Encoding.BigEndianUnicode.GetString(parsedMessage.Data, 0, parsedMessage.Data.Length - 1);

                if (Data[offset] != 0x80)
                {
                    parsedMessage.Type = DataMessageType.String;
                }
                else
                {
                    int ipAddressesOffset = offset;
                    parsedMessage.Type = (DataMessageType)Data[offset + 1];

                    // is it client data message to server (joining game)
                    if (Data[offset + 1] == 4)
                    {
                        ipAddressesOffset += 6;
                    }
                    // is it server data message to client (joining game)
                    else if (Data[offset + 1] == 5)
                    {
                        ipAddressesOffset += 8;
                    }
                    // is it server data message to client (got Invitation)
                    // is it client data message to server (sent Invitation)
                    else if (Data[offset + 1] == 0)
                    {
                        ipAddressesOffset += 7;
                    }
                    // invitation timeout
                    else if (Data[offset + 1] == 3)
                    {
                        ipAddressesOffset += 7;
                    }
                    else if (parsedMessage.Type == DataMessageType.InvitationResponse)
                    {
                        bool inviteAccepted = Data[offset + 2] == 1;
                    }
                    else
                    {
                        // Unknown yet
                    }

                    var ipAddressBytes = new byte[] {
                                Data[ipAddressesOffset],
                                Data[ipAddressesOffset + 1],
                                Data[ipAddressesOffset + 2],
                                Data[ipAddressesOffset + 3],
                        };
                    parsedMessage.ipAddress = new IPAddress(ipAddressBytes);

                    var ipAddressSecondaryBytes = new byte[] {
                                Data[ipAddressesOffset + 16],
                                Data[ipAddressesOffset + 17],
                                Data[ipAddressesOffset + 18],
                                Data[ipAddressesOffset + 19],
                        };
                    parsedMessage.ipAddressSecondary = new IPAddress(ipAddressSecondaryBytes);

                    return parsedMessage;
                }

                return parsedMessage;
            }
        }

        public class DataMessageStringServer : MessageServer
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// Data Length
            /// </summary>
            public Int16 DataLength;

            /// <summary>
            /// Username, variable length, ends with \0
            /// </summary>
            public string Username;

            /// <summary>
            /// DataMessage as a string
            /// </summary>
            public string DataString;

            public DataMessageStringServer(string Username, string DataString)
            {
                if (!Username.EndsWith("\0"))
                {
                    Username += "\0";
                }
                if (!DataString.EndsWith("\0"))
                {
                    DataString += "\0\0\0\0";
                }

                this.Username = Username;
                this.DataString = DataString;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.DATA_MSG;
            }

            public override byte[] GetBytes()
            {
                byte[] DataStringBytes = Encoding.BigEndianUnicode.GetBytes(DataString);

                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 2 + Username.Length + DataStringBytes.Length), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes((short)(DataStringBytes.Length)), 0, 2);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(Username), 0, Username.Length);
                memoryStream.Write(DataStringBytes, 0, DataStringBytes.Length);
                return memoryStream.ToArray();
            }
        }

        public class DataMessageServer : MessageServer
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// Data Length
            /// </summary>
            public Int16 DataLength;

            /// <summary>
            /// Username, variable length, ends with \0
            /// </summary>
            public string Username;

            /// <summary>
            /// DataMessage as a string
            /// </summary>
            public byte[] Data;

            public DataMessageServer(string Username, byte[] Data)
            {
                if (!Username.EndsWith("\0"))
                {
                    Username += "\0";
                }

                this.Username = Username;
                this.Data = Data;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.DATA_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 2 + Username.Length + Data.Length), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes((short)(Data.Length)), 0, 2);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(Username), 0, Username.Length);
                memoryStream.Write(Data, 0, Data.Length);
                return memoryStream.ToArray();
            }
        }

        public class DataMessageAck : MessageServer
        {
            /// <summary>
            /// Unused
            /// </summary>
            public Int32 Unused_0 = 0;

            /// <summary>
            /// Unknown
            /// </summary>
            public Int16 Unknown_0 = 0;

            /// <summary>
            /// Username, ends with '\0'
            /// </summary>
            public string Username;

            public DataMessageAck(string Username)
            {
                if (!Username.EndsWith("\0"))
                {
                    Username += "\0";
                }

                this.Username = Username;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE.DATA_ACK_MSG;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(4 + 2 + Username.Length), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(Unused_0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 2);
                memoryStream.Write(System.Text.Encoding.ASCII.GetBytes(Username), 0, Username.Length);
                return memoryStream.ToArray();
            }
        }

        public class RoomConnectMessage : MessageClient
        {
            /// <summary>
            /// Always 1818387065, 'ybbl', 'lbby' backwards, short for lobby
            /// </summary>
            public Int32 Signature;

            /// <summary>
            /// Always 23
            /// </summary>
            public Int32 Unknown_0;

            /// <summary>
            /// Always 0x1000 or 65536. This is also used in ErrorMessage, ConnectMessage and ConnectRoomMessage
            /// </summary>
            public Int32 Unknown_1;

            /// <summary>
            /// Chat name. Max 32 chars, '\0' terminated
            /// </summary>
            public String ChatName;

            public Int32 AppID;

            public Int16 Unknown_TotalGamesPlayed;

            public Int16 Unknown_TotalWins;

            public Int16 Unknown_2;

            public Int16 Unknown_3;

            public Int16 ESORating;

            public Int16 FavouriteGod;

            public ZoneClient.AppID GetAppID()
            {
                return (AppID & 0x10) == 0 ? ZoneClient.AppID.AoM : ZoneClient.AppID.AoT;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.ROOM_CONNECT;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedMessage = new RoomConnectMessage();
                parsedMessage.Signature = BitConverter.ToInt32(Data, 0);
                parsedMessage.Unknown_0 = BitConverter.ToInt32(Data, 4);
                parsedMessage.Unknown_1 = BitConverter.ToInt32(Data, 8);

                parsedMessage.ChatName = System.Text.Encoding.ASCII.GetString(Data, 12, 64);
                parsedMessage.ChatName =
                    parsedMessage.ChatName.TrimEnd('\0') + '\0';

                parsedMessage.AppID = BitConverter.ToInt32(Data, 76);
                parsedMessage.Unknown_TotalGamesPlayed = BitConverter.ToInt16(Data, 80);
                parsedMessage.Unknown_TotalWins = BitConverter.ToInt16(Data, 82);
                parsedMessage.Unknown_2 = BitConverter.ToInt16(Data, 84);
                parsedMessage.Unknown_3 = BitConverter.ToInt16(Data, 86);
                parsedMessage.ESORating = BitConverter.ToInt16(Data, 88);
                parsedMessage.FavouriteGod = BitConverter.ToInt16(Data, 90);

                return parsedMessage;
            }
        }

        public class RoomAccessedMessage : MessageServer
        {
            public short UserLobbyID;

            public RoomAccessedMessage(short UserLobbyID)
            {
                this.UserLobbyID = UserLobbyID;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.ROOM_ACCESSED;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(5256), 0, 4);

                memoryStream.Write(BitConverter.GetBytes(UserLobbyID), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)0), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(0), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(1), 0, 4);
                memoryStream.Write(BitConverter.GetBytes((short)1), 0, 2);
                memoryStream.Write(Encoding.ASCII.GetBytes("zlaunch.dll".PadRight(32, '\0')), 0, 32);
                memoryStream.Write(Encoding.ASCII.GetBytes("LobbyRes.dll".PadRight(32, '\0')), 0, 32);
                memoryStream.Write(Encoding.ASCII.GetBytes("Age 2 Expansion".PadRight(64, '\0')), 0, 64);
                memoryStream.Write(Encoding.ASCII.GetBytes("{5DE93F3F-FC90-4ee1-AE5A-63DAFA055950}".PadRight(64, '\0')), 0, 64);
                memoryStream.Write(Encoding.ASCII.GetBytes("1.0A".PadRight(16, '\0')), 0, 16);
                memoryStream.Write(BitConverter.GetBytes(131147), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(1048584), 0, 4);
                memoryStream.Write(BitConverter.GetBytes((short)0), 0, 2);

                memoryStream.Write(Encoding.ASCII.GetBytes(
                    @"Software\Microsoft\Microsoft Games\Age of Empires II: The Conquerors Expansion\1.0".PadRight(1024, '\0'))
                    , 0, 1024);
                memoryStream.Write(Encoding.ASCII.GetBytes(
                    "We are not able to detect Age 2 Expansion installed on your hard drive. Please install the game before matchmaking on the Zone.".PadRight(256, '\0'))
                    , 0, 256);
                memoryStream.Write(Encoding.ASCII.GetBytes(
                    "You have an old version of Age 2 Expansion. Click on Go To Downloads to get the latest patch installed.".PadRight(256, '\0'))
                    , 0, 256);

                memoryStream.Write(Encoding.ASCII.GetBytes("Version".PadRight(128, '\0')), 0, 128);
                memoryStream.Write(Encoding.ASCII.GetBytes("EXE Path".PadRight(128, '\0')), 0, 128);
                memoryStream.Write(BitConverter.GetBytes(20), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(182960667616870403), 0, 8);

                memoryStream.Write(new byte[3220], 0, 3220);

                return memoryStream.ToArray();
            }
        }

        public class InfoRecord
        {
            /// <summary>
            /// The unique ID for this infoRecord
            /// </summary>
            public Int32 ID;

            /// <summary>
            /// Usually 0
            /// </summary>
            public Int32 Unknown_0 = 0;

            /// <summary>
            /// Username, 32 chars, terminates in '\0'
            /// </summary>
            public string Username;

            /// <summary>
            /// Contains the 4 byte of IP address, in reverse order
            /// </summary>
            public byte[] ipAddress = new byte[4];

            /// <summary>
            /// Usually 0
            /// </summary>
            public Int32 Unknown_1 = 0;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_2 = -1;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_3 = -1;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_4 = -1;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_5 = -1;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_6 = -1;

            /// <summary>
            /// 0
            /// </summary>
            public Int16 Unknown_7 = 0;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_8 = -1;

            /// <summary>
            /// -1
            /// </summary>
            public Int16 Unknown_9 = -1;

            public Int16 AppID = 1;

            public Int16 Unknown_10 = 0;

            public Int16 Unknown_TotalGamesPlayed;

            public Int16 Unknown_TotalWins;

            public Int16 Unknown_11;

            public Int16 Unknown_12;

            public Int16 ESORating = 1600;

            public Int16 FavouriteGod = -1;

            public ZoneClient.AppID GetAppID()
            {
                return AppID == 1 ? ZoneClient.AppID.AoM : ZoneClient.AppID.AoT;
            }

            public InfoRecord(ZoneClient zoneClient)
            {
                this.ID = zoneClient.UserLobbyID;
                this.Username = zoneClient.Username.PadRight(32, '\0');
                this.AppID = (short)(zoneClient.CurrentAppID == ZoneClient.AppID.AoM ? 1 : 2);
                this.ipAddress = zoneClient.UserIPAddress.GetAddressBytes();
                Array.Reverse(this.ipAddress);
            }

            public byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(ID), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);
                memoryStream.Write(Encoding.ASCII.GetBytes(Username), 0, 32);
                memoryStream.Write(ipAddress, 0, 4);
                memoryStream.Write(BitConverter.GetBytes(Unknown_1), 0, 4);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_2), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_3), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_4), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_5), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_6), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_7), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_8), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_9), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)AppID), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)Unknown_10), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unknown_TotalGamesPlayed), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unknown_TotalWins), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unknown_11), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unknown_12), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(ESORating), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(FavouriteGod), 0, 2);

                return memoryStream.ToArray();
            }
        }

        public class RoomInfoMessage : MessageServer
        {
            /// <summary>
            /// Seen value: 8
            /// </summary>
            public Int16 Unused_0 = 8;

            /// <summary>
            /// User Count
            /// </summary>
            public Int16 InfoRecordsCount
            {
                get
                {
                    return (short)InfoRecords.Length;
                }
            }

            /// <summary>
            /// Unknown
            /// </summary>
            public Int32 Unknown_0 = 0;

            public InfoRecord[] InfoRecords;

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.ROOM_INFO;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(2 + 2 + 4 + 80 * InfoRecordsCount + 60 * Unknown_0 + 4), 0, 4);
                memoryStream.Write(BitConverter.GetBytes((short)Unused_0), 0, 2);
                memoryStream.Write(BitConverter.GetBytes((short)InfoRecordsCount), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unknown_0), 0, 4);

                foreach (var infoRecord in InfoRecords)
                {
                    var bytes = infoRecord.GetBytes();
                    memoryStream.Write(bytes, 0, bytes.Length);
                }
                memoryStream.Write(new byte[4], 0, 4);

                return memoryStream.ToArray();
            }
        }

        public class EnterMessage : MessageServer
        {

            public InfoRecord UserInfoRecord;

            public EnterMessage(InfoRecord UserInfoRecord)
            {
                this.UserInfoRecord = UserInfoRecord;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.ENTER;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(80), 0, 4);
                var bytes = UserInfoRecord.GetBytes();
                memoryStream.Write(bytes, 0, bytes.Length);

                return memoryStream.ToArray();
            }
        }

        public class LeaveMessage : MessageServer
        {

            public InfoRecord UserInfoRecord;

            public LeaveMessage(InfoRecord UserInfoRecord)
            {
                this.UserInfoRecord = UserInfoRecord;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.LEAVE;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(80), 0, 4);
                var bytes = UserInfoRecord.GetBytes();
                memoryStream.Write(bytes, 0, bytes.Length);

                return memoryStream.ToArray();
            }
        }

        public class TalkMessage : MessageClient
        {
            /// <summary>
            /// The ID for the user on the chat\lobby
            /// </summary>
            public Int32 ID;

            /// <summary>
            /// Message Length (Zip byte length)
            /// </summary>
            public Int16 MessageLength;

            /// <summary>
            /// Sometimes it's 0, sometimes it isnt'
            /// </summary>
            public Int16 Unkown_0;

            /// <summary>
            /// The compressed string
            /// </summary>
            public byte[] MessageZipped;

            /// <summary>
            /// Message unzipped.
            /// </summary>
            public string Message
            {
                get
                {
                    using (ZInputStream zInputStream = new ZInputStream(new MemoryStream(MessageZipped)))
                    {
                        byte[] bytes = new byte[1024];
                        int len = 0;
                        while (zInputStream.read(bytes, len, MessageLength) > 0)
                        {
                            len = (int)zInputStream.TotalOut;
                        }

                        byte[] stringBytes = new byte[len];
                        Array.Copy(bytes, stringBytes, len);
                        return Encoding.Unicode.GetString(stringBytes, 0, len);
                    }
                }
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.TALK;
            }

            public override MessageClient Parse(Message message)
            {
                byte[] Data = message.Data;
                var parsedMessage = new TalkMessage();
                parsedMessage.ID = BitConverter.ToInt32(Data, 0);
                parsedMessage.MessageLength = BitConverter.ToInt16(Data, 4);
                parsedMessage.Unkown_0 = BitConverter.ToInt16(Data, 6);

                parsedMessage.MessageZipped = new byte[parsedMessage.MessageLength];

                Array.Copy(Data, 8, parsedMessage.MessageZipped, 0, parsedMessage.MessageLength);
                string lol = parsedMessage.Message;
                return parsedMessage;
            }
        }

        public class TalkResponseMessage : MessageServer
        {
            /// <summary>
            /// The Username, max length 32, '\0' terminated
            /// </summary>
            public string Username;

            /// <summary>
            /// Message Length (Zip byte length)
            /// </summary>
            public Int16 MessageLength
            {
                get
                {
                    return (Int16)Message.Length;
                }
            }

            /// <summary>
            /// Sometimes it's 0, sometimes it isnt'
            /// </summary>
            //public Int16 Unkown_0 = 0;

            /// <summary>
            /// The compressed string
            /// </summary>
            public byte[] MessageZipped
            {
                get
                {
                    var memoryStream = new MemoryStream();
                    using (ZOutputStream zOutputStream = new ZOutputStream(memoryStream, zlib.zlibConst.Z_BEST_COMPRESSION))
                    {
                        var stringBytes = Encoding.Unicode.GetBytes(Message);
                        zOutputStream.Write(stringBytes, 0, stringBytes.Length);
                    }
                    return memoryStream.ToArray();
                }
            }

            /// <summary>
            /// Message unzipped.
            /// </summary>
            public string Message;

            public TalkResponseMessage(InfoRecord InfoRecord, string Message)
            {
                this.Username = InfoRecord.Username.PadRight(32, '\0');
                if (!Message.EndsWith("\0"))
                {
                    Message += '\0';
                }
                this.Message = Message;
            }

            public TalkResponseMessage(string Username, string Message)
            {
                this.Username = Username.PadRight(32, '\0');
                if (!Message.EndsWith("\0"))
                {
                    Message += '\0';
                }
                this.Message = Message;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.TALK_RESPONSE;
            }

            public override byte[] GetBytes()
            {
                var stringZippedBytes = MessageZipped;
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(32 + 2 + stringZippedBytes.Length + 1), 0, 4);
                memoryStream.Write(Encoding.ASCII.GetBytes(Username), 0, 32);
                memoryStream.Write(BitConverter.GetBytes(stringZippedBytes.Length + 1), 0, 2);
                //memoryStream.Write(BitConverter.GetBytes(Unkown_0), 0, 2);
                memoryStream.Write(stringZippedBytes, 0, stringZippedBytes.Length);
                memoryStream.WriteByte(0);

                return memoryStream.ToArray();
            }
        }

        public class TalkResponseIDMessage : MessageServer
        {
            /// <summary>
            /// The ID for the user on the chat\lobby
            /// </summary>
            public Int32 ID;

            /// <summary>
            /// Message Length (Zip byte length)
            /// </summary>
            public Int16 MessageLength
            {
                get
                {
                    return (Int16)Message.Length;
                }
            }

            /// <summary>
            /// Sometimes it's 0, sometimes it isnt'
            /// </summary>
            public Int16 Unkown_0 = 0;

            /// <summary>
            /// The compressed string
            /// </summary>
            public byte[] MessageZipped
            {
                get
                {
                    var memoryStream = new MemoryStream();
                    using (ZOutputStream zOutputStream = new ZOutputStream(memoryStream, zlib.zlibConst.Z_BEST_COMPRESSION))
                    {
                        var stringBytes = Encoding.Unicode.GetBytes(Message);
                        zOutputStream.Write(stringBytes, 0, stringBytes.Length);
                    }
                    return memoryStream.ToArray();
                }
            }

            /// <summary>
            /// Message unzipped.
            /// </summary>
            public string Message;

            public TalkResponseIDMessage(InfoRecord InfoRecord, string Message)
            {
                this.ID = InfoRecord.ID;
                if (!Message.EndsWith("\0"))
                {
                    Message += '\0';
                }
                this.Message = Message;
            }

            public TalkResponseIDMessage(Int32 ID, string Message)
            {
                this.ID = ID;
                if (!Message.EndsWith("\0"))
                {
                    Message += '\0';
                }
                this.Message = Message;
            }

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.TALK_RESPONSE_ID;
            }

            public override byte[] GetBytes()
            {
                var stringZippedBytes = MessageZipped;
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(8 + stringZippedBytes.Length + 1), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(ID), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(stringZippedBytes.Length + 1), 0, 2);
                memoryStream.Write(BitConverter.GetBytes(Unkown_0), 0, 2);
                memoryStream.Write(stringZippedBytes, 0, stringZippedBytes.Length);
                memoryStream.WriteByte(0);

                return memoryStream.ToArray();
            }
        }

        public class DisconnectMessage : MessageServer
        {

            public override Int32 GetTypeID()
            {
                return (Int32)Messages.SIGNATURE_CHAT.DISCONNECT;
            }

            public override byte[] GetBytes()
            {
                var memoryStream = new MemoryStream();
                memoryStream.Write(BitConverter.GetBytes(GetTypeID()), 0, 4);
                memoryStream.Write(BitConverter.GetBytes(0), 0, 4);

                return memoryStream.ToArray();
            }
        }
    }
}
