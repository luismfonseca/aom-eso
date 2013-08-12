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
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace ESO_Zone_Server.Protocol
{
    public class ZoneClient
    {
        public const Int32 DEFAULT_SECURE_KEY = -131647931;

        public enum UserProtocolState
        {
            Connecting,
            GeneratingSecurityContext,
            ExchangingFirstSecureMessage,
            Authenticating,
            ConnectingProtocol,
            Online,
            Offline
        }

        public enum AppID
        {
            AoM = 0,
            AoT = 1,
            Offline = 3
        }

        public enum UserState
        {
            Offline = 3,
            HostingGame = 2,
            HostingGameAlt = 7,
            JoinedGame = 8,
            PlayingGame = 6,
            Searching = 4,
            StartingGame = 10,
            Away = 5,
            Busy = 4,
            Postgame = 11,
            OnlineRatedLounge = 12,
            OnlineAdvancedLounge = 13
        }

        public UInt32 SequenceID = 0;

        public Int32 SecureKey = DEFAULT_SECURE_KEY;

        public string Username;

        public int UserID;

        public short UserLobbyID;

        public IPAddress UserIPAddress;

        public bool IsOnLobby
        {
            get
            {
                return Lobby != null;
            }
        }

        public ZoneLobby Lobby = null;

        public UserProtocolState CurrentProtocolState;

        public AppID CurrentAppID;

        public UserState CurrentUserState = UserState.Offline;

        public bool IsProcessingOrSendingPackets = false;

        public ObservableCollection<string> WatchList = new ObservableCollection<string>();

        internal ObservableRangeCollection<IZonePacket> packetsToBeSent = new ObservableRangeCollection<IZonePacket>();
    }
}
