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

namespace ESOSniffer
{
    public struct Message
    {
        public enum TYPE_ID
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

        /// <summary>
        /// The type of this message.
        /// </summary>
        public Int32 TypeID;

        /// <summary>
        /// The size or length of the Message - this is excluding the Zone Headers
        /// </summary>
        public Int32 Size;

        /// <summary>
        /// The data it conveys.
        /// </summary>
        public byte[] Data;

        private static Message Parse(byte[] rawMessageData)
        {
            var parsedMessage = new Message();
            parsedMessage.TypeID = BitConverter.ToInt32(rawMessageData, 0);
            parsedMessage.Size = BitConverter.ToInt32(rawMessageData, 4);
            if (parsedMessage.TypeID != (Int32)TYPE_ID.PING_MSG)
            {
                parsedMessage.Data = new byte[parsedMessage.Size];
                if (parsedMessage.Data.Length > rawMessageData.Length - 8)
                {
                    throw new ESOSniffer.ZonePacket.NotEnoughBytesException();
                    // this should really not happen since it show had been thrown in ZonePacket.Parse before it got here
                }
                else
                {
                    Array.Copy(rawMessageData, 8, parsedMessage.Data, 0, parsedMessage.Size);
                }
            }

            return parsedMessage;
        }

        public static Message Parse(ZonePacket Packet)
        {
            return Message.Parse(Packet.Data);
        }
    }
}
