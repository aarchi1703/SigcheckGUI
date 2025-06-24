using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SigcheckGUI
{
    public class YaraSettings
    {
        private static readonly string YARA_SETTINGS_FILE = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "yara_rules.txt");
        private static YaraSettings _instance;
        private List<YaraRule> _rules;

        public static YaraSettings Instance
        {
            get
            {
                if (_instance == null)
                {
                    _instance = new YaraSettings();
                }
                return _instance;
            }
        }

        private YaraSettings()
        {
            _rules = new List<YaraRule>();
            LoadSettings();
        }

        public List<YaraRule> Rules
        {
            get => _rules;
            set
            {
                _rules = value;
                SaveSettings();
            }
        }

        public void AddRule(YaraRule rule)
        {
            _rules.Add(rule);
            SaveSettings();
        }

        public void RemoveRule(YaraRule rule)
        {
            _rules.Remove(rule);
            SaveSettings();
        }

        public void UpdateRule(YaraRule oldRule, YaraRule newRule)
        {
            var index = _rules.IndexOf(oldRule);
            if (index != -1)
            {
                _rules[index] = newRule;
                SaveSettings();
            }
        }

        private void SaveSettings()
        {
            try
            {
                List<string> lines = new List<string>();
                foreach (var rule in _rules)
                {
                    string line = $"{rule.Enabled}|{rule.RulePath}|{rule.Description}";
                    lines.Add(line);
                }
                File.WriteAllLines(YARA_SETTINGS_FILE, lines);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при сохранении настроек YARA: {ex.Message}");
            }
        }

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(YARA_SETTINGS_FILE))
                {
                    string[] lines = File.ReadAllLines(YARA_SETTINGS_FILE);
                    foreach (string line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = line.Split('|');
                        if (parts.Length >= 2)
                        {
                            YaraRule rule = new YaraRule
                            {
                                Enabled = bool.Parse(parts[0]),
                                RulePath = parts[1],
                                Description = parts.Length >= 3 ? parts[2] : string.Empty
                            };
                            _rules.Add(rule);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при загрузке настроек YARA: {ex.Message}");
                _rules = new List<YaraRule>();
            }
        }
    }
} 