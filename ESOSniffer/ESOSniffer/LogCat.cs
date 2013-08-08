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

using ESOSniffer.Protocol;
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

namespace ESOSniffer
{
    public partial class LogCat : Form
    {
        public LogCat()
        {
            InitializeComponent();
            FlowAnalyzer.logHandler = Connections.logHandler = text =>
            {
                this.Invoke((MethodInvoker)delegate
                {
                    lbLog.Items.Add(text);

                    int visibleItems = lbLog.ClientSize.Height / lbLog.ItemHeight;
                    lbLog.TopIndex = Math.Max(lbLog.Items.Count - visibleItems + 1, 0);
                });
            };

            var t = new Thread(Connections.Start);
            
            t.Start();
        }

        private void lbLog_DoubleClick(object sender, EventArgs e)
        {
            string item = lbLog.SelectedItems[0] as string;
            int index = item.IndexOf("SequenceID[");
            if (index == -1)
            {
                return;
            }
            index += "SequenceID[".Length;
            int indexEnd = item.IndexOf("]", index);


            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "explorer";
            psi.Arguments = string.Format("/root,{0} /select,{1}", 
                System.IO.Directory.GetCurrentDirectory(), item.Substring(index, indexEnd - index));
            psi.UseShellExecute = true;

            Process newProcess = new Process();
            newProcess.StartInfo = psi;
            newProcess.Start();
        }
    }
}
