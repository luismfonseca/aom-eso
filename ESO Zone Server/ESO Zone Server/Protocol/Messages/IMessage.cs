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
    public interface IMessage
    {
        Int32 GetTypeID();
    }

    public abstract class MessageClient : IMessage
    {
        abstract public Int32 GetTypeID();

        abstract public MessageClient Parse(Message message);

        public bool CanParse(Message message, bool isLobby)
        {
            return message.TypeID == GetTypeID();
        }
    }

    public abstract class MessageServer : IMessage
    {
        abstract public Int32 GetTypeID();

        abstract public byte[] GetBytes();
    }
}
