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

namespace ESOSniffer.Protocol
{
    public struct FirstZonePacket
    {
        public static Int32 ZCONN_FIRST_MSG_TYPE_KEY = 0x00FD1801;
        
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
        public Int32 SecureKey;

        /// <summary>
        /// This is the initial sequence ID. Client messages sent to server will be +1 from this value on.
        /// </summary>
        public Int32 SequenceID;

        public static FirstZonePacket Parse(byte[] rawData)
        {
            ZonePacket.xorBytes(ref rawData, -131647931);

            var parsedPacket = new FirstZonePacket();
            parsedPacket.Signature = BitConverter.ToInt32(rawData, 0);

            parsedPacket.UnionType = BitConverter.ToInt32(rawData, 4);
            if (parsedPacket.UnionType != 18414848)
            {
                //chat server UnionType = 8322048
                //throw new Exception("Unsupported union type.");
            }

            parsedPacket.SecureKey = BitConverter.ToInt32(rawData, 8);

            parsedPacket.SequenceID = BitConverter.ToInt32(rawData, 12);

            return parsedPacket;
        }
    }
}
