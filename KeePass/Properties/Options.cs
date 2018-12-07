using KeePass.Plugins;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeeLogs.Properties
{
    class Options
    {
        private IPluginHost m_host = null;
        private string m_PluginName = "TitleDisplay";

        private string m_sCustom = "Secure DB";
        public string Custom
        {
            get { return m_sCustom; }
            set { m_sCustom = value; }
        }

        private long m_lMaxTitleLen = 64;
        public long MaxTitleLen
        {
            get { return m_lMaxTitleLen; }
            set { m_lMaxTitleLen = value; }
        }

        /// <summary>
        /// 1: Database Name
        /// 2: File Name
        /// 3: Custom
        /// 4: DefaultUserName
        /// 5: Database Description
        /// 6: Database RootGroup Name
        /// 7: File Path
        /// </summary>
        private long m_lOption = 2;
        public long Option
        {
            get { return m_lOption; }
            set { m_lOption = value; }
        }

        private bool m_bShowProductName = true;
        public bool ShowProductName
        {
            get { return m_bShowProductName; }
            set { m_bShowProductName = value; }
        }

        public Options(IPluginHost host)
        {
            m_host = host;

            m_sCustom = m_host.CustomConfig.GetString(m_PluginName + ".Custom", m_sCustom);
            m_lOption = m_host.CustomConfig.GetLong(m_PluginName + ".Option", m_lOption);
            m_bShowProductName = m_host.CustomConfig.GetBool(m_PluginName + ".ShowProductName", m_bShowProductName);
            m_lMaxTitleLen = m_host.CustomConfig.GetLong(m_PluginName + ".MaxTitleLen", m_lMaxTitleLen);
        }

        public void Save()
        {
            m_host.CustomConfig.SetString(m_PluginName + ".Custom", m_sCustom);
            m_host.CustomConfig.SetLong(m_PluginName + ".Option", m_lOption);
            m_host.CustomConfig.SetBool(m_PluginName + ".ShowProductName", m_bShowProductName);
            m_host.CustomConfig.SetLong(m_PluginName + ".MaxTitleLen", m_lMaxTitleLen);
        }
    }
}

