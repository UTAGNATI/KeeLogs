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

        internal class Entry
        {
            // Auto-implemented properties.
            public string Uuid { get; set; }
            public string Title { get; set; }
            public string UserName { get; set; }
            public string Password { get; set; }
        }

        private IList<Entry> oldEntriesList;

        private ToolStripSeparator m_tsSeparator = null;
        private ToolStripMenuItem m_tsmiPopup = null;
        private ToolStripMenuItem m_tsmiAddGroups = null;
        private ToolStripMenuItem m_tsmiAddEntries = null;

        private string pathForLogs = @"D:\TAGNATI\source\Logs.txt";

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
            m_tsmiAddGroups.Text = "Choisir l'emplacement des Logs";
            m_tsmiAddGroups.Click += ChoosePath;
            m_tsmiPopup.DropDownItems.Add(m_tsmiAddGroups);

            m_host.TriggerSystem.RaisingEvent += this.OnEcasEvent;
            //m_host.MainWindow.GetSelectedEntry(true).Touched += this.OnSavedEntry; je comprend pas comment Touched focntionne

            GlobalWindowManager.WindowRemoved += this.OnSavedEntry; //eventhandler sur la fermeture d'une fenetre quelconque (pas seulement une fenetre de modification d'entrée !!!)
            //GlobalWindowManager.WindowAdded +=; //trouver comment savoir si c'est une fenetre d'ajout qui vient de s'ouvirir

            return true;
        }

        //Permet d'enregistrer les dates de modification de toutes les entrées ainsi que toutes les valeurs des champs
        internal IList<Entry> FindLastModEnt(PwDatabase pd) 
        {
            IList<Entry> lResults = new List<Entry>();

            Entry newEntry;

            PwObjectList<PwEntry> lEntries = m_host.Database.RootGroup.GetEntries(true);

            foreach (PwEntry pe in lEntries)
            {

                newEntry = new Entry{Uuid = pe.Uuid.ToHexString() , UserName = pe.Strings.ReadSafe(PwDefs.UserNameField), Title = pe.Strings.ReadSafe(PwDefs.TitleField), Password = pe.Strings.ReadSafe(PwDefs.PasswordField) };
                lResults.Add(newEntry);
            }

            return lResults;
        }

        //Permet de comparer deux listes d'Entry/PwEntry
        internal void EntriesListCompare(IList<Entry> oldEntriesList, PwEntry selectedEntry)
        {
            if(selectedEntry == null)
            {
                return;
            }

            PwObjectList<PwEntry> lEntries = m_host.Database.RootGroup.GetEntries(true);

            foreach (Entry e in oldEntriesList)
            {
                if(e.Uuid.Equals(selectedEntry.Uuid.ToHexString())) //si l'élément est bien le même au niveau du ID
                {
                    if (e.Title != selectedEntry.Strings.ReadSafe(PwDefs.TitleField))
                    {
                        // genere un log disant que l'entrée en question a été modifiée sous la forme "pe.LasModificationTime L'entrée e.Uuid a été modifié / oldTitle : ... - newTitle : ...

                        File.AppendAllText(pathForLogs, selectedEntry.LastModificationTime + " L'entrée " + e.Uuid + " à été modifié / oldTitle : " + e.Title + " - newTitle : " + selectedEntry.Strings.ReadSafe(PwDefs.TitleField) + Environment.NewLine);

                        e.Title = selectedEntry.Strings.ReadSafe(PwDefs.TitleField); //on met à jour la oldEntriesList en cas de re-modification
                    }
                    if (e.UserName != selectedEntry.Strings.ReadSafe(PwDefs.UserNameField))
                    {
                        // genere un log disant que l'entrée en question a été modifiée sous la forme "pe.LasModificationTime L'entrée e.Uuid.ToHexString() a été modifié / oldUserName : ... - newUserName : ...

                        File.AppendAllText(pathForLogs, selectedEntry.LastModificationTime + " L'entrée " + e.Uuid + " à été modifié / oldUsername : " + e.UserName + " - newUsername : " + selectedEntry.Strings.ReadSafe(PwDefs.UserNameField) + Environment.NewLine);

                        e.UserName = selectedEntry.Strings.ReadSafe(PwDefs.UserNameField); //on met à jour la oldEntriesList en cas de re-modification
                    }
                    if (e.Password != selectedEntry.Strings.ReadSafe(PwDefs.PasswordField))
                    {
                        // genere un log disant que l'entrée en question a été modifiée sous la forme "pe.LasModificationTime L'entrée e.Uuid.ToHexString() a été modifié / oldPassword : ... - newPassword : ...

                        File.AppendAllText(pathForLogs, selectedEntry.LastModificationTime + " L'entrée " + e.Uuid + " à été modifié / oldPassword : " + e.Password + " - newPassword : " + selectedEntry.Strings.ReadSafe(PwDefs.PasswordField) + Environment.NewLine);

                        e.Password = selectedEntry.Strings.ReadSafe(PwDefs.PasswordField); //on met à jour la oldEntriesList en cas de re-modification
                    }
                }
            }
        }

        internal void checkMaJ(IList<Entry> oldEntriesList) 
        {
            if (!m_host.Database.IsOpen)
            {      
                return;
            }

            PwObjectList<PwEntry> lEntries = m_host.Database.RootGroup.GetEntries(true);

            if (oldEntriesList.Count() == lEntries.Count())
            {
                MessageBox.Show(oldEntriesList.Count().ToString() +"\n"+ lEntries.Count().ToString());
            }
            else if(oldEntriesList.Count() < lEntries.Count())
            {
                //ajout d'un element
                MessageBox.Show(oldEntriesList.Count().ToString() + "\n" + lEntries.Count().ToString());
            }
            else if (oldEntriesList.Count() > lEntries.Count())
            {
                //suppression d'un element
                MessageBox.Show(oldEntriesList.Count().ToString() + "\n" + lEntries.Count().ToString());
            }
        }

        private void OnEcasEvent(object sender, EcasRaisingEventArgs e)
        {
            if (e.Event.Type.Equals(CopiedEntryInfo))
            {
                File.AppendAllText(pathForLogs, DateTime.Today.ToString("dd-MM-yyyy ") + " / " + DateTime.Now.ToString("HH:mm:ss") + " L'entrée suivante a été copiée dans le presse-papier : " + m_host.MainWindow.GetSelectedEntry(true).Uuid.ToHexString() + Environment.NewLine);
            }
            else if (e.Event.Type.Equals(OpenedDatabaseFile))
            {
                //appel d'une fcontion qui enregistre l'etat actuel de la bdd
                oldEntriesList = FindLastModEnt(m_host.Database);

                File.AppendAllText(pathForLogs, DateTime.Today.ToString("dd-MM-yyyy ") + " / " + DateTime.Now.ToString("HH:mm:ss")  + "Ouverture de la Database" + Environment.NewLine);
            }
            else if (e.Event.Type.Equals(ClosingDatabaseFilePost))
            {

                File.AppendAllText(pathForLogs, DateTime.Today.ToString("dd-MM-yyyy ") + " / " + DateTime.Now.ToString("HH:mm:ss") + "Fermeture de la Database" + Environment.NewLine);

                //recuperation de l'état actuel de la bdd + comparaison avec celle enregistrée à l'ouverture de la bdd pour voir les différences et les logger
                EntriesListCompare(oldEntriesList, m_host.MainWindow.GetSelectedEntry(true)); 

                //reste encore à log les ajouts et suppressions d'entrées
            }
        }

        private void OnSavedEntry(object sender, GwmWindowEventArgs e)
        {
            EntriesListCompare(oldEntriesList, m_host.MainWindow.GetSelectedEntry(true));
            checkMaJ(oldEntriesList);
        }

        private void ChoosePath(object sender, EventArgs e)
        {
            if (!m_host.Database.IsOpen)
            {
                MessageBox.Show("Vous devez ouvrir une database d'abord!", "Formind Plugin");
                return;
            }

            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.Description = "Choisir un chemin";
            dialog.ShowDialog();
            if (dialog.SelectedPath.Equals(""))
            {
                return;
            }

            // Open up filestream
            FileStream fs;
            try
            {
                fs = new FileStream(Path.Combine(dialog.SelectedPath, "Logs.txt"), FileMode.Create);
                pathForLogs = Path.Combine(dialog.SelectedPath, "Logs.txt");
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show("Accès refusé");
                return;
            }

        }

        public override void Terminate()
        {

            // Remove all of our menu items
            ToolStripItemCollection tsMenu = m_host.MainWindow.ToolsMenu.DropDownItems;
            tsMenu.Remove(m_tsSeparator);
            tsMenu.Remove(m_tsmiPopup);
            tsMenu.Remove(m_tsmiAddGroups);
            tsMenu.Remove(m_tsmiAddEntries);

            // Important! Remove event handlers!
            m_host.MainWindow.FileSaved -= OnFileSaved;
            //m_host.MainWindow.GetSelectedEntry(true).Touched -= OnSavedEntry;

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