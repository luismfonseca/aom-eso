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
using System.Text;
using System.Threading.Tasks;

namespace ESO_Zone_Server.Protocol.Packet
{
    public struct FirstZonePacket : IZonePacket
    {
        public enum UnionTypes
        {
            ZCONN_FIRST_MSG = 18414848,
            ZCHAT_FIRST_MSG = 8322048
        }

        public static Int32 ZCONN_FIRST_MSG_TYPE_KEY = 18414848;

        /// <summary>
        /// This is always eNoZ
        /// </summary>
        public Int32 Signature;

        /// <summary>
        /// Must be 0x00FD1801 or 18414848 for the first message
        /// </summary>
        public Int32 UnionType;

        /// <summary>
        /// This will be used to XOR future messages.
        /// Note: The server replies with the 4 bytes always equals, for example: 0xF0F0F0F0
        /// </summary>
        public UInt32 SecureKey;

        /// <summary>
        /// This is the initial sequence ID. Client messages sent to server will be +1 from this value on.
        /// </summary>
        public UInt32 SequenceID;

        public FirstZonePacket(UInt32 secureKey, UInt32 sequenceID, UnionTypes unionType)
        {
            this.Signature = ZonePacket.ZONE_SIGNATURE;
            this.UnionType = (Int32)unionType;
            this.SecureKey = secureKey;
            this.SequenceID = sequenceID;
        }

        public byte[] GetBytes(Int32 secureKey)
        {
            var memoryStream = new MemoryStream();
            memoryStream.Write(BitConverter.GetBytes(Signature), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(UnionType), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(SecureKey), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(SequenceID), 0, 4);
            byte[] packetBytes = memoryStream.ToArray();

            ZonePacket.xorBytes(ref packetBytes, ZoneClient.DEFAULT_SECURE_KEY);
            return packetBytes;
        }
    }
}
