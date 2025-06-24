using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using System.Linq;

namespace SigcheckGUI
{
    public class FileHistoryEntry
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public DateTime ProcessedDate { get; set; }
        public Dictionary<string, string> TabContents { get; set; } = new Dictionary<string, string>();
        public List<AlarmSetting> AppliedAlarmSettings { get; set; } = new List<AlarmSetting>();
        public List<YaraRule> AppliedYaraRules { get; set; } = new List<YaraRule>();
        public string YaraScanResults { get; set; }
        public string EntropyValue { get; set; }
        public string VirusTotalResults { get; set; }
        public bool RecursiveCheck { get; set; }
        public bool RevocationCheck { get; set; }
        public int AlarmCount { get; set; }
    }

    public class FileHistory
    {
        private const string HISTORY_FILE = "file_history.json";
        private static FileHistory _instance;
        private static readonly object _lock = new object();

        public static FileHistory Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new FileHistory();
                        }
                    }
                }
                return _instance;
            }
        }

        public List<FileHistoryEntry> Entries { get; private set; } = new List<FileHistoryEntry>();

        private FileHistory()
        {
            LoadHistory();
        }

        public void AddEntry(FileHistoryEntry entry)
        {
            lock (_lock)
            {
                Entries.RemoveAll(e => e.FilePath.Equals(entry.FilePath, StringComparison.OrdinalIgnoreCase));
                
                Entries.Insert(0, entry);
                
                Entries = Entries.OrderByDescending(e => e.ProcessedDate).ToList();
                
                if (Entries.Count > 100)
                {
                    Entries = Entries.Take(100).ToList();
                }
                
                SaveHistory();
            }
        }

        public void ClearHistory()
        {
            lock (_lock)
            {
                Entries.Clear();
                SaveHistory();
            }
        }

        public void SaveHistory()
        {
            lock (_lock)
            {
                try
                {
                    string json = JsonConvert.SerializeObject(Entries, Formatting.Indented);
                    File.WriteAllText(HISTORY_FILE, json);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Ошибка при сохранении истории: {ex.Message}");
                }
            }
        }

        public void CleanupDuplicateEntries()
        {
            lock (_lock)
            {
                var uniqueEntries = new List<FileHistoryEntry>();
                var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                
                foreach (var entry in Entries)
                {
                    if (!seenPaths.Contains(entry.FilePath))
                    {
                        seenPaths.Add(entry.FilePath);
                        uniqueEntries.Add(entry);
                    }
                }
                
                Entries = uniqueEntries;
                SaveHistory();
            }
        }

        public FileHistoryEntry GetEntryByFilePath(string filePath)
        {
            lock (_lock)
            {
                return Entries.FirstOrDefault(e => e.FilePath.Equals(filePath, StringComparison.OrdinalIgnoreCase));
            }
        }

        private void LoadHistory()
        {
            try
            {
                if (File.Exists(HISTORY_FILE))
                {
                    string json = File.ReadAllText(HISTORY_FILE);
                    Entries = JsonConvert.DeserializeObject<List<FileHistoryEntry>>(json) ?? new List<FileHistoryEntry>();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при загрузке истории: {ex.Message}");
                Entries = new List<FileHistoryEntry>();
            }
        }
    }
} 