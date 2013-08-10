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

using ESO_Zone_Server.Protocol;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ESO_Zone_Server
{
    public partial class Log : Form
    {
        private static Log logInstance;

        public Log()
        {
            InitializeComponent();
        }

        private static void LogMessage(string message)
        {
            logInstance.Invoke((MethodInvoker)delegate
            {
                logInstance.lbLog.Items.Add(message);

                int visibleItems = logInstance.lbLog.ClientSize.Height / logInstance.lbLog.ItemHeight;
                logInstance.lbLog.TopIndex = Math.Max(logInstance.lbLog.Items.Count - visibleItems + 1, 0);
            });
        }

        public static void Inform(string tag, string message)
        {
            LogMessage("[i]" + "[" + tag + "] " + message);
        }

        public static void Debug(string tag, string message)
        {
            LogMessage("[d]" + "[" + tag + "] " + message);
        }

        public static void Warning(string tag, string message)
        {
            LogMessage("[w]" + "[" + tag + "] " + message);
        }

        private void Log_Load(object sender, EventArgs e)
        {
            logInstance = this;

            // Start Message Server
            var thread = new Thread(ASyncServer.Start);
            thread.Start(Zone.MSG_PORT);

            // Start Chat\Lobby Server
            for (int i = 0; i < Zone.CHAT_COUNT; i++)
            {
                var threadChat = new Thread(ASyncServer.Start);
                threadChat.Start(Zone.CHAT_PORT + i);
            }
        }
    }
}
