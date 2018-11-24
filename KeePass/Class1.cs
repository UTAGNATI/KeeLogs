using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePass.Util;
using KeePassLib;
using KeePass.Ecas;
using KeePass.Plugins;
using KeePass.Util;

using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Utility;

namespace KeePass
{
    public sealed class KeePassExt : Plugin
    {
        private IPluginHost m_host = null;

        private IList<string> lastModList;

        private ToolStripSeparator m_tsSeparator = null;
        private ToolStripMenuItem m_tsmiPopup = null;
        private ToolStripMenuItem m_tsmiAddGroups = null;
        private ToolStripMenuItem m_tsmiAddEntries = null;

        public static readonly PwUuid OpenedDatabaseFile = new PwUuid(new byte[] {
            0xE5, 0xFF, 0x13, 0x06, 0x85, 0xB8, 0x41, 0x89,
            0xB9, 0x06, 0xF6, 0x9E, 0x2B, 0x3B, 0x40, 0xA7
        });

        public static readonly PwUuid ClosingDatabaseFilePost = new PwUuid(new byte[] {
            0x94, 0xFA, 0x70, 0xE5, 0xB1, 0x3F, 0x41, 0x26,
            0xA6, 0x4E, 0x06, 0x4F, 0xD8, 0xC3, 0x6C, 0x95
        });

        private static readonly PwUuid CopiedEntryInfo = new PwUuid(new byte[] {
            0x3F, 0x7E, 0x5E, 0xC6, 0x2A, 0x54, 0x4C, 0x58,
            0x95, 0x44, 0x85, 0xFB, 0xF2, 0x6F, 0x56, 0xDC
        });

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;

            ToolStripItemCollection tsMenu = m_host.MainWindow.ToolsMenu.DropDownItems;

            m_tsSeparator = new ToolStripSeparator();
            tsMenu.Add(m_tsSeparator);

            // Add the popup menu item
            m_tsmiPopup = new ToolStripMenuItem();
            m_tsmiPopup.Text = "FormindPlugin";
            tsMenu.Add(m_tsmiPopup);

            // Add menu item 'Add Some Groups'
            m_tsmiAddGroups = new ToolStripMenuItem();
            m_tsmiAddGroups.Text = "Test";
            m_tsmiAddGroups.Click += OnMenuAddGroups;
            m_tsmiPopup.DropDownItems.Add(m_tsmiAddGroups);

            m_host.TriggerSystem.RaisingEvent += this.OnEcasEvent;
            AutoType.FilterSend += this.OnAutoType;

            return true;
        }

        public IList<string> FindLastModEnt(PwDatabase pd)
        {
            PwObjectList<PwEntry> lEntries = m_host.Database.RootGroup.GetEntries(true);
            IList<string> lResults = new List<string>();

            string newLine;

            foreach (PwEntry pe in lEntries)
            {
                newLine = pe.Strings.ReadSafe(PwDefs.TitleField) + " " + pe.Strings.ReadSafe(PwDefs.UserNameField) + " " + TimeUtil.ToDisplayString(pe.LastModificationTime);
                lResults.Add(newLine);
            }

            return lResults;
        }

        private void OnEcasEvent(object sender, EcasRaisingEventArgs e)
        {
            if (e.Event.Type.Equals(CopiedEntryInfo))
            {
                lastModList = FindLastModEnt(m_host.Database);
                File.AppendAllText(@"D:\TAGNATI\source\Logs.txt", m_host.MainWindow.GetSelectedEntry(true).Strings.ReadSafe(PwDefs.TitleField) + " has been copied to the clipboar at " + m_host.MainWindow.GetSelectedEntry(true).LastAccessTime + "\nLast modification the : " + m_host.MainWindow.GetSelectedEntry(true).LastModificationTime + Environment.NewLine);
                
            }

            // else if entrée modifiée

            else if (e.Event.Type.Equals(OpenedDatabaseFile))
            {
                lastModList = FindLastModEnt(m_host.Database);
                File.AppendAllText(@"D:\TAGNATI\source\Logs.txt", "Ouverture de la Database" + DateTime.Now.ToString("HH:mm:ss") + " / " + DateTime.Today.ToString("dd-MM-yyyy") + Environment.NewLine);

            }
            else if (e.Event.Type.Equals(ClosingDatabaseFilePost))
            {
                lastModList = FindLastModEnt(m_host.Database);
                foreach (String entry in lastModList)
                {
                    File.AppendAllText(@"D:\TAGNATI\source\Logs.txt", entry + Environment.NewLine);
                }
                File.AppendAllText(@"D:\TAGNATI\source\Logs.txt", "Fermeture de la Database" + DateTime.Now.ToString("HH:mm:ss") + " / " + DateTime.Today.ToString("dd-MM-yyyy") + Environment.NewLine);

            }
        }

        private void OnAutoType(object sender, AutoTypeEventArgs e)
        {
            // e.Sequence will be auto-typed
        }

        private void OnMenuAddGroups(object sender, EventArgs e)
        {
            if (!m_host.Database.IsOpen)
            {
                MessageBox.Show("You first need to open a database!", "Formind Plugin");
                return;
            }

            MessageBox.Show(m_host.Database.Name);

            //CreateAndShowEntryList(EntryReportDelegate f);


        }

        public override void Terminate()
        {
            //ecrit la liste de toutes les dernières modifications dans un fichier txt
            //System.IO.File.WriteAllLines(@"D:\TAGNATI\source\TestLogPlugin.txt", lastModList);

            // Remove all of our menu items
            ToolStripItemCollection tsMenu = m_host.MainWindow.ToolsMenu.DropDownItems;
            tsMenu.Remove(m_tsSeparator);
            tsMenu.Remove(m_tsmiPopup);
            tsMenu.Remove(m_tsmiAddGroups);
            tsMenu.Remove(m_tsmiAddEntries);

            // Important! Remove event handlers!
            m_host.MainWindow.FileSaved -= OnFileSaved;
        }

        private void OnFileSaved(object sender, FileSavedEventArgs e)
        {
            MessageBox.Show("Notification received: the user has tried to save the current database to:\r\n" +
                m_host.Database.IOConnectionInfo.Path + "\r\n\r\nResult:\r\n" +
                (e.Success ? "Success" : "Failed"), "Formind Plugin",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}