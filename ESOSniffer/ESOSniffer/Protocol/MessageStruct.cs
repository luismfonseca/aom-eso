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
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace ESOSniffer.Protocol
{
    public static class MessageStruct
    {
        public interface IMessageStruct
        {
        }
        
        public enum AppID
        {
            Offline = 0,
            AoM = 1,
            AoT = 2
        }

        public struct FirstSecureMessage : IMessageStruct
        {
            /// <summary>
            /// Always 2054382947, or 'cesz' which is zsec backwards. Short for ZSecurityMessage
            /// </summary>
            public Int32 ID;

            /// <summary>
            /// Always 1 (gameID?)
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// I've seen B0E93372, B0E9F06B, or all 0s
            /// </summary>
            public Int32 Unkown_1;

            public static FirstSecureMessage Parse(byte[] Data)
            {
                var parsedFirstSecureMessage = new FirstSecureMessage();
                parsedFirstSecureMessage.ID = BitConverter.ToInt32(Data, 0);
                parsedFirstSecureMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);
                //parsedFirstSecureMessage.Unkown_1 = BitConverter.ToInt32(Data, 8);

                return parsedFirstSecureMessage;
            }
        }

        public struct FirstSecureMessageServer : IMessageStruct
        {
            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Always "ZWebAuth"
            /// </summary>
            public string ZWebAuthSignature;

            /// <summary>
            /// Some values, not sure if they are important
            /// </summary>
            public byte[] Unkown_1;

            public static FirstSecureMessageServer Parse(byte[] Data)
            {
                var parsedMessage = new FirstSecureMessageServer();
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.ZWebAuthSignature = System.Text.Encoding.ASCII.GetString(Data, 4, 8);
                parsedMessage.Unkown_1 = new byte[44];
                Buffer.BlockCopy(Data, 12, parsedMessage.Unkown_1, 0, parsedMessage.Unkown_1.Length);

                return parsedMessage;
            }
        }

        public struct GenerateSecurityContext : IMessageStruct
        {
            /// <summary>
            /// 'cesz', meaning zSecurityRequest
            /// </summary>
            public string ZSecurityRequestSignature;

            /// <summary>
            /// Always 1 (maybe it's AppID?)
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Always 2054644014. Or ".awz", "zwa." backwards. Might mean ZWatchMessage
            /// </summary>
            public string ZWatchSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unkown_1;

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

            // this message also has pw encrypted
            public static GenerateSecurityContext Parse(byte[] Data)
            {
                var parsedMessage = new GenerateSecurityContext();
                parsedMessage.ZSecurityRequestSignature = System.Text.Encoding.ASCII.GetString(Data, 0, 4);
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 8, 4);
                parsedMessage.Unkown_1 = BitConverter.ToInt32(Data, 12);
                parsedMessage.UserID = BitConverter.ToInt32(Data, 16);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 20, 4);
                parsedMessage.UserEncryptedPassword = new byte[32];
                Buffer.BlockCopy(Data, 24, parsedMessage.UserEncryptedPassword, 0, parsedMessage.UserEncryptedPassword.Length);

                return parsedMessage;
            }
        }

        public struct SecurityContextServer : IMessageStruct
        {
            /// <summary>
            /// Always 1 (maybe it's AppID?)
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// "ZWebAuth" or 0x5A5765624175746800
            /// </summary>
            public string ID;

            /// <summary>
            /// Fixed size and fixed message.
            /// When xor'ed with 0x78, we get 4E6F5A2B000000E3783796205F09CE012000002300000000000000000001009A0800005741544348
            /// Starts with "NoZ+" or "+ZoN" backwards.
            /// </summary>
            public byte[] Unkown_1;

            /// <summary>
            /// Always 2054644014. Or ".awz", "zwa." backwards. Might mean ZWatchMessage
            /// </summary>
            public string ZWatchSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unkown_2;

            /// <summary>
            /// Random key sent by server. Maybe used to encrypt Passkey?
            /// </summary>
            public Int64 Unkown_Key;

            /// <summary>
            /// Always 115, or 0x7300
            /// </summary>
            public Int16 Unkown_3;

            /// <summary>
            /// Always 0
            /// </summary>
            public byte Unkown_4;

            public static SecurityContextServer Parse(byte[] Data)
            {
                var parsedMessage = new SecurityContextServer();
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.ID = System.Text.Encoding.ASCII.GetString(Data, 4, 9);

                parsedMessage.Unkown_1 = new byte[40];
                Buffer.BlockCopy(Data, 13, parsedMessage.Unkown_1, 0, parsedMessage.Unkown_1.Length);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 53, 4);
                parsedMessage.Unkown_2 = BitConverter.ToInt32(Data, 57);
                parsedMessage.Unkown_Key = BitConverter.ToInt64(Data, 61);
                parsedMessage.Unkown_3 = BitConverter.ToInt16(Data, 69);
                parsedMessage.Unkown_4 = Data[71];

                return parsedMessage;
            }
        }

        public struct AuthenticateMessage : IMessageStruct
        {
            /// <summary>
            /// 'cesz', meaning zSecurityRequest
            /// </summary>
            public string ZSecurityRequestSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Always 2054644014. Or ".awz", "zwa." backwards. Might mean ZWatchMessage
            /// </summary>
            public string ZWatchSignature;

            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unkown_1;

            /// <summary>
            /// Not sure, but it's always 20 bytes long.
            /// </summary>
            public byte[] Unkown_2;

            public static AuthenticateMessage Parse(byte[] Data)
            {
                var parsedMessage = new AuthenticateMessage();
                parsedMessage.ZSecurityRequestSignature = System.Text.Encoding.ASCII.GetString(Data, 0, 4);
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);

                parsedMessage.ZWatchSignature = System.Text.Encoding.ASCII.GetString(Data, 8, 4);
                parsedMessage.Unkown_1 = BitConverter.ToInt32(Data, 12);
                parsedMessage.Unkown_2 = new byte[20];
                Buffer.BlockCopy(Data, 13, parsedMessage.Unkown_2, 0, parsedMessage.Unkown_2.Length);

                return parsedMessage;
            }
        }

        public struct ServerAccessDenied : IMessageStruct
        {
            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// ID for reason being denied. (?)
            /// Wrong passkey or username: 16842756
            /// Chat server once replied: 16908292
            /// </summary>
            public Int32 Reason;

            public static ServerAccessDenied Parse(byte[] Data)
            {
                var parsedMessage = new ServerAccessDenied();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.Reason = BitConverter.ToInt32(Data, 4);
                return parsedMessage;
            }
        }

        public struct ServerAccessGranted : IMessageStruct
        {
            /// <summary>
            /// Always 1
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always "ZWebAuth", ending with \0
            /// </summary>
            public string ZWebAuthSignature;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_1;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_2;

            /// <summary>
            /// Username, Maximum length of 19
            /// </summary>
            public string Username;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_3;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_4;

            /// <summary>
            /// I don't think this is used
            /// </summary>
            public Int32 Unused_5;

            /// <summary>
            /// UserID=<xxxxxxx> ending in \0
            /// </summary>
            public string UserID;

            public static ServerAccessGranted Parse(byte[] Data)
            {
                var parsedMessage = new ServerAccessGranted();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.ZWebAuthSignature = System.Text.Encoding.ASCII.GetString(Data, 4, 8);
                parsedMessage.Unused_1 = BitConverter.ToInt32(Data, 13);
                parsedMessage.Unused_2 = BitConverter.ToInt32(Data, 17);
                parsedMessage.Username = System.Text.Encoding.ASCII.GetString(Data, 21, 19);

                parsedMessage.Unused_3 = BitConverter.ToInt32(Data, 41);
                parsedMessage.Unused_4 = BitConverter.ToInt32(Data, 45);
                parsedMessage.Unused_5 = BitConverter.ToInt32(Data, 49);

                parsedMessage.UserID = System.Text.Encoding.ASCII.GetString(Data, 53, Data.Length - 53);
                return parsedMessage;
            }
        }

        public struct ConnectMessage : IMessageStruct
        {
            /// <summary>
            /// Always 0
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always 0x1000 or 65536. This is also used in ErrorMessage
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Always "BLTP 1.0"
            /// </summary>
            public string ProtocolSignature;

            public static ConnectMessage Parse(byte[] Data)
            {
                var parsedMessage = new ConnectMessage();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);
                parsedMessage.ProtocolSignature = System.Text.Encoding.ASCII.GetString(Data, 8, 8);
                return parsedMessage;
            }
        }

        public struct ConnectAckMessage : IMessageStruct
        {
            /// <summary>
            /// Always 0
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always 0x1000 or 65536. This is also used in ErrorMessage
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Contains information about Username, MaxWatches, MaxFilters, MinChatVersion, ChatServer, ChatGuid and ChatData
            /// </summary>
            public string ConfigurationText;

            public static ConnectAckMessage Parse(byte[] Data)
            {
                var parsedMessage = new ConnectAckMessage();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);
                parsedMessage.ConfigurationText = System.Text.Encoding.ASCII.GetString(Data, 8, Data.Length - 8);
                return parsedMessage;
            }
        }

        public struct WatchMessage : IMessageStruct
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always 1 for WatchMessage
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Player's username.
            /// The last char is enconded differently: byteBeforeLast - byteLast.
            /// </summary>
            public String Username;

            /// <summary>
            /// This is a bug. I've fixed it in dll, it can be safely ingored otherwise.
            /// </summary>
            public byte Unkown_1;

            public static WatchMessage Parse(byte[] Data)
            {
                var parsedWatchMessage = new WatchMessage();
                parsedWatchMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedWatchMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);

                parsedWatchMessage.Username = getString(Data, 8, Data.Length - 0 - 8);

                parsedWatchMessage.Unkown_1 = Data.Last();
                return parsedWatchMessage;
            }
        }

        public struct UserMessage : IMessageStruct
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;
            
            /// <summary>
            /// State & 0xFFFFFFEF and AppID & 0x10
            /// </summary>
            public Int32 UserStateAndAppID;

            /// <summary>
            /// Player's username.
            /// The last char is enconded differently: byteBeforeLast - byteLast.
            /// </summary>
            public String Username;

            public AppID getAppID()
            {
                if ((UserStateAndAppID & 0xFFFFFFEF) == 3)
                    return AppID.Offline;

                return (UserStateAndAppID & 0x10) == 0 ? AppID.AoM : AppID.AoT;
            }

            public Int32 getState()
            {
                switch (UserStateAndAppID & 0xFFFFFFEF)
                {
                    case 3: // offline
                        return 0;
                    case 2:
                    case 7:
                        return 1;
                    case 8:
                        return 2;
                    case 6:
                        return 3;
                    case 9:
                        return 4;
                    case 10:
                        return 5;
                    case 5:
                        return 6;
                    case 4:
                        return 7;
                    case 11:
                        return 8;
                    case 12: // online
                        return 9;
                    case 13:
                        return 10;
                    default:
                        return 0;
                }
            }

            public static UserMessage Parse(byte[] Data)
            {
                var parsedUserMessage = new UserMessage();
                parsedUserMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedUserMessage.UserStateAndAppID = BitConverter.ToInt32(Data, 4);
                parsedUserMessage.Username = getString(Data, 8, Data.Length - 8);

                return parsedUserMessage;
            }
        }

        public struct ErrorMessage : IMessageStruct
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// Always 0x1000 or 65536. This is also used in BLTP message
            /// </summary>
            public Int32 Unkown_0;

            /// <summary>
            /// Maybe code error
            /// </summary>
            public Int32 Unkown_1;

            /// <summary>
            /// Message of error
            /// </summary>
            public string Message;

            public static ErrorMessage Parse(byte[] Data)
            {
                var parsedMessage = new ErrorMessage();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.Unkown_0 = BitConverter.ToInt32(Data, 4);
                parsedMessage.Unkown_1 = BitConverter.ToInt32(Data, 8);

                parsedMessage.Message = getString(Data, 12, Data.Length - 12);

                return parsedMessage;
            }
        }

        public struct StateMessage : IMessageStruct
        {
            /// <summary>
            /// Always 0s
            /// </summary>
            public Int32 Unused_0;

            /// <summary>
            /// State & 0xFFFFFFEF and AppID & 0x10
            /// </summary>
            public Int32 UserStateAndAppID;


            public AppID getAppID()
            {
                if ((UserStateAndAppID & 0xFFFFFFEF) == 3)
                    return AppID.Offline;

                return (AppID)((UserStateAndAppID & 0x10) == 0 ? AppID.AoM : AppID.AoT);
            }

            public Int32 getState()
            {
                switch (UserStateAndAppID & 0xFFFFFFEF)
                {
                    case 3:
                        return 0; // offline
                    case 2:
                    case 7:
                        return 1; // hosting game
                    case 8:
                        return 2; // joined game
                    case 6:
                        return 3; // playing game
                    case 9:
                        return 4; // searching
                    case 10:
                        return 5; // starting game
                    case 5:
                        return 6; // away
                    case 4:
                        return 7; // busy
                    case 11:
                        return 8; // game over
                    case 12:
                        return 9; // online @ rated lounge
                    case 13:
                        return 10; // online @ advanced lounge
                    default:
                        return 0; // unkown status
                }
            }

            public static StateMessage Parse(byte[] Data)
            {
                var parsedStateMessage = new StateMessage();
                parsedStateMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedStateMessage.UserStateAndAppID = BitConverter.ToInt32(Data, 4);

                return parsedStateMessage;
            }
        }

        public struct DataMessage : IMessageStruct
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
            /// DataMessage
            /// </summary>
            public string DataString;

            /// <summary>
            /// Data messages can have a string or ips address used to connect players when in advanced mode
            /// </summary>
            public bool isStringMessage;

            /// <summary>
            /// The IP Address
            /// </summary>
            public IPAddress ipAddress;

            /// <summary>
            /// Alternative IP Address
            /// </summary>
            public IPAddress ipAddressSecondary;

            public static DataMessage Parse(byte[] Data)
            {
                var parsedMessage = new DataMessage();
                parsedMessage.Unused_0 = BitConverter.ToInt32(Data, 0);
                parsedMessage.DataLength = BitConverter.ToInt16(Data, 4);

                int offset = 6;
                while (Data[offset++] != 0) ;
                parsedMessage.Username = getString(Data, 6, offset - 6);

                parsedMessage.Data = new byte[parsedMessage.DataLength];
                Buffer.BlockCopy(Data, offset, parsedMessage.Data, 0, parsedMessage.Data.Length);
                parsedMessage.DataString = System.Text.Encoding.BigEndianUnicode.GetString(parsedMessage.Data);

                parsedMessage.isStringMessage = Data[offset + 1] != 0x80; // or alternatively, check if length is pair
                if (parsedMessage.isStringMessage == false)
                {
                    int ipAddressesOffset = offset;

                    // is it client data message to server (joining game)
                    if (BitConverter.ToUInt16(Data, offset) == 0x0480)
                    {
                        ipAddressesOffset += 6;
                    }
                    // is it server data message to client (joining game)
                    else if (BitConverter.ToUInt16(Data, offset) == 0x0580)
                    {
                        ipAddressesOffset += 8;
                    }
                    // is it server data message to client (got Invitation)
                    // is it client data message to server (sent Invitation)
                    else if (BitConverter.ToUInt16(Data, offset) == 0x0080)
                    {
                        ipAddressesOffset += 7;
                    }
                    // invitation timeout
                    else if (BitConverter.ToUInt16(Data, offset) == 0x0380)
                    {
                        ipAddressesOffset += 7;
                    }
                    else
                    {
                        // unkown
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

        private static String getString(byte[] array, int index, int count)
        {
            return System.Text.Encoding.ASCII.GetString(array, index, count);
        }

        public static IMessageStruct ParseMessageData(Message message)
        {
            switch ((Message.TYPE_ID) message.TypeID)
            {
                case Message.TYPE_ID.FIRST_SECURE_MESSAGE:
                    return FirstSecureMessage.Parse(message.Data);
                case Message.TYPE_ID.FIRST_SECURE_MESSAGE_SERVER:
                    return FirstSecureMessageServer.Parse(message.Data);
                case Message.TYPE_ID.GENERATE_SECURITY_CONTEXT:
                    return GenerateSecurityContext.Parse(message.Data);
                case Message.TYPE_ID.SECURITY_CONTEXT_SERVER_MSG:
                    return SecurityContextServer.Parse(message.Data);
                case Message.TYPE_ID.AUTHENTICATE_MSG:
                    return AuthenticateMessage.Parse(message.Data);
                case Message.TYPE_ID.SERVER_ACCESS_GRANTED:
                    return ServerAccessGranted.Parse(message.Data);
                case Message.TYPE_ID.SERVER_ACCESS_DENIED:
                    return ServerAccessDenied.Parse(message.Data);
                case Message.TYPE_ID.CONNECT_MSG:
                    return ConnectMessage.Parse(message.Data);
                case Message.TYPE_ID.CONNECT_ACK_MSG:
                    return ConnectAckMessage.Parse(message.Data);
                case Message.TYPE_ID.STATE_MSG:
                    return StateMessage.Parse(message.Data);
                case Message.TYPE_ID.USER_MSG:
                    return UserMessage.Parse(message.Data);
                case Message.TYPE_ID.ERROR_MSG:
                    return ErrorMessage.Parse(message.Data);
                case Message.TYPE_ID.WATCH_MSG:
                    return WatchMessage.Parse(message.Data);
                case Message.TYPE_ID.DATA_MSG:
                    return DataMessage.Parse(message.Data);
                default:
                    return null;
            }
        }
    }
}
