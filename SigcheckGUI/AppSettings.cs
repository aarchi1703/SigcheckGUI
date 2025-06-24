using System;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace SigcheckGUI
{
    public class AppSettings
    {
        private const string SETTINGS_FILE = "app_settings.json";
        private static AppSettings _instance;
        private static readonly object _lock = new object();

        public static AppSettings Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = LoadSettings();
                        }
                    }
                }
                return _instance;
            }
        }

        public bool EnableIndividualHistorySettings { get; set; } = true;
        public bool RecursiveCheckEnabled { get; set; } = false;
        public bool RevocationCheckEnabled { get; set; } = false;

        public List<AlarmSetting> GlobalAlarmSettings { get; set; } = new List<AlarmSetting>();
        public List<YaraRule> GlobalYaraRules { get; set; } = new List<YaraRule>();

        public string YaraFolderPath { get; set; } = string.Empty;
        public string GithubYaraPath { get; set; } = string.Empty;

        private AppSettings()
        {
        }

        private static AppSettings LoadSettings()
        {
            try
            {
                if (File.Exists(SETTINGS_FILE))
                {
                    System.Diagnostics.Debug.WriteLine("AppSettings.LoadSettings: Файл настроек найден, загружаем...");
                    string json = File.ReadAllText(SETTINGS_FILE);
                    AppSettings settings = JsonConvert.DeserializeObject<AppSettings>(json) ?? new AppSettings();
                    
                    System.Diagnostics.Debug.WriteLine($"AppSettings.LoadSettings: Десериализовано. Алармов: {settings.GlobalAlarmSettings?.Count ?? 0}, YARA: {settings.GlobalYaraRules?.Count ?? 0}");
                    
                    if (settings.GlobalAlarmSettings == null)
                    {
                        System.Diagnostics.Debug.WriteLine("AppSettings.LoadSettings: GlobalAlarmSettings был null, инициализируем пустым списком");
                        settings.GlobalAlarmSettings = new List<AlarmSetting>();
                    }
                    if (settings.GlobalYaraRules == null)
                    {
                        System.Diagnostics.Debug.WriteLine("AppSettings.LoadSettings: GlobalYaraRules был null, инициализируем пустым списком");
                        settings.GlobalYaraRules = new List<YaraRule>();
                    }
                    
                    System.Diagnostics.Debug.WriteLine($"AppSettings.LoadSettings: Финальное количество алармов: {settings.GlobalAlarmSettings.Count}");
                    System.Diagnostics.Debug.WriteLine($"AppSettings.LoadSettings: Финальное количество YARA правил: {settings.GlobalYaraRules.Count}");
                    
                    return settings;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("AppSettings.LoadSettings: Файл настроек не найден, создаем новые настройки (пустые)");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при загрузке настроек приложения: {ex.Message}");
            }
            AppSettings newSettings = new AppSettings();
            newSettings.GlobalAlarmSettings = new List<AlarmSetting>();
            newSettings.GlobalYaraRules = new List<YaraRule>();
            System.Diagnostics.Debug.WriteLine($"AppSettings.LoadSettings: Возвращаем новые пустые настройки. Алармов: {newSettings.GlobalAlarmSettings.Count}, YARA: {newSettings.GlobalYaraRules.Count}");
            return newSettings;
        }

        public void SaveSettings()
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"AppSettings.SaveSettings: Сохраняем {GlobalAlarmSettings.Count} алармов и {GlobalYaraRules.Count} YARA правил");
                
                foreach (var alarm in GlobalAlarmSettings)
                {
                    System.Diagnostics.Debug.WriteLine($"AppSettings.SaveSettings: Сохраняемый аларм: {alarm.Parameter} = {alarm.Value} (Enabled: {alarm.Enabled})");
                }
                
                string json = JsonConvert.SerializeObject(this, Formatting.Indented);
                File.WriteAllText(SETTINGS_FILE, json);
                System.Diagnostics.Debug.WriteLine("AppSettings.SaveSettings: Настройки успешно сохранены");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при сохранении настроек приложения: {ex.Message}");
            }
        }

        public void ResetToDefaults()
        {
            System.Diagnostics.Debug.WriteLine("AppSettings.ResetToDefaults: Сброс всех настроек к стандартным значениям.");
            EnableIndividualHistorySettings = true;
            RecursiveCheckEnabled = false;
            RevocationCheckEnabled = false;
            
            GlobalAlarmSettings = new List<AlarmSetting>();
            GlobalYaraRules = new List<YaraRule>();
            
            System.Diagnostics.Debug.WriteLine("AppSettings.ResetToDefaults: Настройки сброшены. Сохраняем...");
            SaveSettings();
            System.Diagnostics.Debug.WriteLine("AppSettings.ResetToDefaults: Настройки сброшены и сохранены.");
        }
    }
} 