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

using ESO_Zone_Server.Protocol.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ESO_Zone_Server.Protocol.Packet
{
    public struct ZonePacket : IZonePacket
    {
        /// <summary>
        /// This is always eNoZ
        /// </summary>
        public const Int32 ZONE_SIGNATURE = 1517244005; // "eNoZ"

        /// <summary>
        /// Signature for the message (its type)
        /// </summary>
        public Int32 Signature;

        /// <summary>
        /// The size of the data
        /// </summary>
        public Int32 Size;

        /// <summary>
        /// If client sends 0, servers reply will also have 0
        /// </summary>
        public UInt32 SequenceID;

        /// <summary>
        /// XOR all data dwords, XOR'd with 0x12344321 and then reverse bytes
        /// </summary>
        public Int32 CRC;

        /// <summary>
        /// Data
        /// </summary>
        public byte[] Data;

        internal static void xorBytes(ref byte[] rawData, Int32 secureKey)
        {
            var key = BitConverter.GetBytes(secureKey);
            for (int i = 0; i < rawData.Length / 4; i++)
            {
                rawData[i * 4] ^= key[3];
                rawData[i * 4 + 1] ^= key[2];
                rawData[i * 4 + 2] ^= key[1];
                rawData[i * 4 + 3] ^= key[0];
            }
        }

        internal static void xorBytesFixTail(ref byte[] data, Int32 secureKey, int bytesNeedFixing = 0)
        {
            if (bytesNeedFixing == 0 && data.Length % 4 == 0)
            {
                return;
            }

            var key = BitConverter.GetBytes(secureKey);
            Array.Reverse(key);
            if (bytesNeedFixing == 0)
            {
                bytesNeedFixing = data.Length % 4;
            }
            for (int i = data.Length - bytesNeedFixing; i < data.Length; i++)
            {
                data[i] ^= key[i % 4];
            }
        }

        internal static Int32 calculateCRC(byte[] data)
        {
            byte[] computingCRC = new byte[] { 0x12, 0x34, 0x43, 0x21 };
            for (int i = 0; i < data.Length / 4; i++)
            {
                computingCRC[0] ^= data[i * 4];
                computingCRC[1] ^= data[i * 4 + 1];
                computingCRC[2] ^= data[i * 4 + 2];
                computingCRC[3] ^= data[i * 4 + 3];
            }
            Array.Reverse(computingCRC, 0, 4);
            return BitConverter.ToInt32(computingCRC, 0);
        }

        public static ZonePacket Parse(ref byte[] rawData, Int32 secureKey)
        {
            if (rawData.Length < 16)
            {
                throw new NotEnoughBytesException();
            }

            xorBytes(ref rawData, secureKey);

            var parsedPacket = new ZonePacket();
            parsedPacket.Signature = BitConverter.ToInt32(rawData, 0);
            parsedPacket.Size = BitConverter.ToInt32(rawData, 4);
            parsedPacket.SequenceID = BitConverter.ToUInt32(rawData, 8);
            parsedPacket.CRC = BitConverter.ToInt32(rawData, 12);

            parsedPacket.Data = new byte[parsedPacket.Size];
            if (parsedPacket.Data.Length > rawData.Length - 16)
            {
                throw new NotEnoughBytesException();
                // not enough bytes to parse message. This can happen. What do to?
            }
            else
            {
                Array.Copy(rawData, 16, parsedPacket.Data, 0, parsedPacket.Data.Length);

                if (rawData.Length - (parsedPacket.Size + 16) > 0)
                {
                    // This means the packets were nagled, and the key was applied to ending bytes unnecessarily
                    xorBytesFixTail(ref parsedPacket.Data, secureKey);
                }
            }
            // remove from rawData the parsed ZonePacket
            Array.Reverse(rawData);
            Array.Resize(ref rawData, rawData.Length - (parsedPacket.Size + 16));
            Array.Reverse(rawData);
            xorBytes(ref rawData, secureKey);

            // Check CRC
            Int32 computedCRC = calculateCRC(parsedPacket.Data);
            if (computedCRC != parsedPacket.CRC)
            {
                // this might mean the key was applied to the ending bytes unnecessarily. Let's attempt to fix it
                xorBytesFixTail(ref parsedPacket.Data, secureKey, 1);
                if (calculateCRC(parsedPacket.Data) != parsedPacket.CRC)
                {
                    xorBytesFixTail(ref parsedPacket.Data, secureKey, 1); // unapply xor because it wasn't effective
                    xorBytesFixTail(ref parsedPacket.Data, secureKey, 2);
                    if (calculateCRC(parsedPacket.Data) != parsedPacket.CRC)
                    {
                        xorBytesFixTail(ref parsedPacket.Data, secureKey, 2);
                        xorBytesFixTail(ref parsedPacket.Data, secureKey, 3);
                        if (calculateCRC(parsedPacket.Data) != parsedPacket.CRC)
                        {
                            xorBytesFixTail(ref parsedPacket.Data, secureKey, 3);
                            throw new CRCMismatchException(parsedPacket, computedCRC);
                        }
                    }
                }
            }

            return parsedPacket;
        }

        public static ZonePacket? TryParse(byte[] rawData, Int32 secureKey)
        {
            try
            {
                return ZonePacket.Parse(ref rawData, secureKey);
            }
            catch
            {
                return null;
            }
        }

        public byte[] GetBytes(Int32 secureKey)
        {
            var memoryStream = new MemoryStream();
            memoryStream.Write(BitConverter.GetBytes(Signature), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(Size), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(SequenceID), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(CRC), 0, 4);
            memoryStream.Write(Data, 0, Data.Length);
            byte[] packetBytes = memoryStream.ToArray();

            xorBytes(ref packetBytes, secureKey);
            return packetBytes;
        }

        public static IZonePacket FromMessage(MessageServer message, ZoneClient zoneClientState)
        {
            Int32 secureKey = zoneClientState.SecureKey;
            UInt32 sequenceID = zoneClientState.SequenceID++;

            var messageBytes = message.GetBytes();
            var newZonePacket = new ZonePacket();
            newZonePacket.Signature = ZONE_SIGNATURE;
            newZonePacket.Size = messageBytes.Length;
            newZonePacket.SequenceID = sequenceID;
            newZonePacket.CRC = calculateCRC(messageBytes);
            newZonePacket.Data = message.GetBytes();
            return newZonePacket;
        }

        public class NotEnoughBytesException : Exception
        {
        }

        public class CRCMismatchException : Exception
        {
            public ZonePacket ParsedPacket;
            public Int32 ComputedCRC;

            public CRCMismatchException(ZonePacket ParsedPacket, Int32 ComputedCRC)
            {
                this.ParsedPacket = ParsedPacket;
                this.ComputedCRC = ComputedCRC;
            }
        }
    }
}
