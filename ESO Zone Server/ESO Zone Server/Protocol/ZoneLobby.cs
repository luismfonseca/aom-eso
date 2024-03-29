﻿using ESO_Zone_Server.Protocol.Messages;
using ESO_Zone_Server.Protocol.Packet;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ESO_Zone_Server.Protocol
{
    public class ZoneLobby
    {
        public const Int16 DEFAULT_USER_ID = 371;

        public ObservableCollection<ZoneClient> Users = new ObservableCollection<ZoneClient>();

        public ObservableCollection<Tuple<short, string>> Messages = new ObservableCollection<Tuple<short, string>>();

        public Dictionary<short, string> UsernamesByID = new Dictionary<short, string>();

        public ZoneLobby()
        {
            Users.CollectionChanged += (sender, args) =>
            {
                if (Users.Count == 0)
                {
                    Messages.Clear();
                    UsernamesByID.Clear();
                }
                else
                {
                    switch (args.Action)
                    {
                        case NotifyCollectionChangedAction.Add:
                            {
                                var zoneClient = args.NewItems[0] as ZoneClient;
                                // Notify others
                                var enterMessage = new Messages.Messages.EnterMessage(
                                    new Messages.Messages.InfoRecord(zoneClient));

                                Users.ForEach(_ => { _.packetsToBeSent.Add(ZonePacket.FromMessage(enterMessage, _)); });

                                // Send Room Info to user
                                var roomInfoMessage = new Messages.Messages.RoomInfoMessage();
                                roomInfoMessage.InfoRecords =
                                    Users.Select(_ => new Messages.Messages.InfoRecord(_)).ToArray();
                                zoneClient.packetsToBeSent.Add(ZonePacket.FromMessage(roomInfoMessage, zoneClient));

                                // Send Messages
                                // What if player left?... Using TalkResponse instead
                                var chatLog = Messages.Select(message =>
                                    {
                                        MessageServer talkMessage;
                                        if (Users.Count(zClient => zClient.UserLobbyID == message.Item1) == 0)
                                        {
                                            talkMessage = new Messages.Messages.TalkResponseMessage(UsernamesByID[(short)message.Item1], message.Item2);
                                        }
                                        else
                                        {
                                            talkMessage = new Messages.Messages.TalkResponseIDMessage(message.Item1, message.Item2);
                                        }
                                        return ZonePacket.FromMessage(talkMessage, zoneClient);
                                    }).ToList();

                                zoneClient.packetsToBeSent.AddRange(chatLog);
                                break;
                            }
                        case NotifyCollectionChangedAction.Remove:
                            {
                                var zoneClient = args.OldItems[0] as ZoneClient;
                                if (Messages.Count(message => ((short)message.Item1) == zoneClient.UserLobbyID) > 0)
                                {
                                    UsernamesByID.Add(zoneClient.UserLobbyID, zoneClient.Username);
                                }

                                var leaveMessage = new Messages.Messages.LeaveMessage(
                                    new Messages.Messages.InfoRecord(zoneClient));

                                Users.ForEach(_ => { _.packetsToBeSent.Add(ZonePacket.FromMessage(leaveMessage, _)); });
                                break;
                            }
                    }
                }
            };
            Messages.CollectionChanged += (sender, args) =>
            {
                switch (args.Action)
                {
                    case NotifyCollectionChangedAction.Remove:
                        {
                            var userLobbyID = ((Tuple<short, string>)args.OldItems[0]).Item1;
                            if (Messages.Count(message => ((short)message.Item1) == userLobbyID) == 0)
                            {
                                UsernamesByID.Remove(userLobbyID);
                            }
                            return;
                        }
                    case NotifyCollectionChangedAction.Reset:
                        return;
                    case NotifyCollectionChangedAction.Add:
                        {
                            var userLobbyID = ((Tuple<short, string>)args.NewItems[0]).Item1;
                            var message = ((Tuple<short, string>)args.NewItems[0]).Item2;

                            var talkMessage = new Messages.Messages.TalkResponseIDMessage(userLobbyID, message);
                            Users.ForEach(_ => { _.packetsToBeSent.Add(ZonePacket.FromMessage(talkMessage, _)); });
                            return;
                        }
                }
            };
        }

        public short GetNextAvailableUserLobbyID()
        {
            short id;
            for (id = ZoneLobby.DEFAULT_USER_ID; id < short.MaxValue; id++)
            {
                if (Users.Count(zoneClient => zoneClient.UserLobbyID == id) == 0
                 && Messages.Count(message => ((short)message.Item1) == id) == 0)
                {
                    return id;
                }
            }

            return -1;
        }
    }
}
