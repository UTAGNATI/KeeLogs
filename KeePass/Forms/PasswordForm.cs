using KeePass.UI;
using KeePass.Plugins;
using KeePass.Resources;
using KeePass;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.ComponentModel;
using System.Drawing;
using System.Diagnostics;

namespace KeeLogs.Forms
{
    public partial class PasswordForm : Form
    {
        private KeeLogs.KeeLogsExt m_Funcs = null;

        public PasswordForm()
        {
            InitializeComponent();
        }

        public void InitEx(IPluginHost host)
        {
            Debug.Assert(host != null);
            m_Funcs = new KeeLogs.KeeLogsExt(host);
        }

        private void OnFormLoad()
        {
            GlobalWindowManager.AddWindow(this);
        }
    }
}
