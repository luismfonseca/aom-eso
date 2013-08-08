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

using ESO_Zone_Server.Protocol.Packet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ESO_Zone_Server.Protocol.Messages
{
    public struct Message
    {
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

        internal static MessageClient Parse(ZonePacket packet, bool isLobby = false)
        {
            byte[] rawMessageData = packet.Data;
            var parsedMessageStructure = new Message();
            parsedMessageStructure.TypeID = BitConverter.ToInt32(rawMessageData, 0);
            parsedMessageStructure.Size = BitConverter.ToInt32(rawMessageData, 4);
            if (parsedMessageStructure.TypeID != (Int32)Messages.SIGNATURE.PING_MSG)
            {
                parsedMessageStructure.Data = new byte[parsedMessageStructure.Size];
                if (parsedMessageStructure.Data.Length > rawMessageData.Length - 8)
                {
                    throw new Protocol.Packet.ZonePacket.NotEnoughBytesException();
                    // this should really not happen since it show had been thrown in ZonePacket.Parse before it got here
                }
                else
                {
                    Array.Copy(rawMessageData, 8, parsedMessageStructure.Data, 0, parsedMessageStructure.Size);
                }
            }

            var messageClientParser = Messages.getAllClientMessages()
                    .SingleOrDefault(message => message.CanParse(parsedMessageStructure, isLobby));

            if (messageClientParser == null)
            {
                Log.Debug("Message", "Message Client Parser not found for Type ID["
                    + parsedMessageStructure.TypeID + "]");
                return null;
            }

            var parsedMessage = messageClientParser.Parse(parsedMessageStructure);

            return parsedMessage;
        }
    }
}
