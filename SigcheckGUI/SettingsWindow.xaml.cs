using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using SigcheckGUI;
using System.IO;
using Newtonsoft.Json;
using System.Windows.Interop;
using System.Runtime.InteropServices;
using System.Net;
using System.IO.Compression;
using System.Threading.Tasks;

namespace SigcheckGUI
{

    public partial class SettingsWindow : Window
    {
        private MainWindow mainWindow;
        private List<SettingsGroup> _displaySettingsGroups; 
        private BindingList<YaraRule> _yaraRulesBindingList;
        private string _lastGithubYaraFolder = null;



        public SettingsWindow(MainWindow mainWindow)
        {
            InitializeComponent();
            this.mainWindow = mainWindow;

            _displaySettingsGroups = new List<SettingsGroup>();

            LoadDisplaySettings();

            _yaraRulesBindingList = new BindingList<YaraRule>(YaraSettings.Instance.Rules);
            yaraRulesItemsControl.ItemsSource = _yaraRulesBindingList;

            checkBoxEnableIndividualHistorySettings.IsChecked = AppSettings.Instance.EnableIndividualHistorySettings;
            checkBoxEnableIndividualHistorySettings.Checked += CheckBoxEnableIndividualHistorySettings_Changed;
            checkBoxEnableIndividualHistorySettings.Unchecked += CheckBoxEnableIndividualHistorySettings_Changed;

            this.Hide();
            this.AllowDrop = true;
            this.Closing += SettingsWindow_Closing;
        }

        private void LoadDisplaySettings()
        {
            _displaySettingsGroups.Clear();

            var initialGroups = new List<SettingsGroup>
            {
                new SettingsGroup
                {
                    GroupName = "Проверка подписи",
                    Settings = new List<AlarmSetting>
                    {
                        new AlarmSetting { Parameter = "Verified", Condition = "Не 'Signed'", Value = "", Tab = "All Info (-a)", Description = "Проверка наличия цифровой подписи файла" },
                        new AlarmSetting { Parameter = "Signing date", Condition = "Дата <", Value = "1980-01-01", Tab = "All Info (-a)", Description = "Проверка даты подписания файла" }
                    }
                },
                new SettingsGroup
                {
                    GroupName = "Проверка версий",
                    Settings = new List<AlarmSetting>
                    {
                        new AlarmSetting { Parameter = "File version", Condition = "Версия <", Value = "X.X.X.X", Tab = "All Info (-a)", Description = "Проверка версии файла" },
                        new AlarmSetting { Parameter = "Prod version", Condition = "Версия <", Value = "X.X.X.X", Tab = "All Info (-a)", Description = "Проверка версии продукта" },
                        new AlarmSetting { Parameter = "Binary Version", Condition = "Версия <", Value = "X.X.X.X", Tab = "All Info (-a)", Description = "Проверка бинарной версии" }
                    }
                },
                new SettingsGroup
                {
                    GroupName = "Проверка энтропии",
                    Settings = new List<AlarmSetting>
                    {
                        new AlarmSetting { Parameter = "Энтропия секций", Condition = ">", Value = "5.5", Tab = "Энтропия", Description = "Проверка энтропии отдельных секций" },
                        new AlarmSetting { Parameter = "Общая энтропия файла", Condition = ">", Value = "5.5", Tab = "Энтропия", Description = "Проверка общей энтропии файла" }
                    }
                },
                new SettingsGroup
                {
                    GroupName = "Проверка VirusTotal",
                    Settings = new List<AlarmSetting>
                    {
                        new AlarmSetting { Parameter = "VT detection", Condition = ">", Value = "0", Tab = "VirusTotal (-v)", Description = "Проверка количества обнаружений в VirusTotal" }
                    }
                },
                new SettingsGroup
                {
                    GroupName = "Дополнительные проверки",
                    Settings = new List<AlarmSetting>
                    {
                        new AlarmSetting { Parameter = "assemblyIdentity", Condition = "Содержит", Value = "MyApplication.app", Tab = "Manifest (-m)", Description = "Проверка идентификатора сборки" },
                        new AlarmSetting { Parameter = "Publisher", Condition = "Содержит", Value = "?", Tab = "All Info (-a)", Description = "Проверка издателя" },
                        new AlarmSetting { Parameter = "Comments", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка комментариев файла" },
                        new AlarmSetting { Parameter = "Company", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка названия компании" },
                        new AlarmSetting { Parameter = "Description", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка описания файла" },
                        new AlarmSetting { Parameter = "Original Name", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка оригинального имени файла" },
                        new AlarmSetting { Parameter = "Internal Name", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка внутреннего имени файла" }
                    }
                }
            };

            foreach (var group in initialGroups)
            {
                var newGroup = new SettingsGroup { GroupName = group.GroupName, Settings = new List<AlarmSetting>() };
                foreach (var setting in group.Settings)
                {
                    var savedSetting = mainWindow.AlarmSettings.FirstOrDefault(s => s.Parameter == setting.Parameter);
                    if (savedSetting != null)
                    {
                        savedSetting.Description = setting.Description;
                        newGroup.Settings.Add(savedSetting);
                        System.Diagnostics.Debug.WriteLine($"SettingsWindow LoadDisplaySettings: Добавлена существующая настройка: {savedSetting.Parameter}, Value: {savedSetting.Value}, Enabled: {savedSetting.Enabled}, Description: {savedSetting.Description}");
                    }
                    else
                    {
                        setting.Enabled = true; 
                        newGroup.Settings.Add(setting);
                        System.Diagnostics.Debug.WriteLine($"SettingsWindow LoadDisplaySettings: Добавлена новая дефолтная настройка: {setting.Parameter}, Value: {setting.Value}, Enabled: {setting.Enabled}, Description: {setting.Description}");
                    }
                }
                _displaySettingsGroups.Add(newGroup);
            }
            settingsItemsControl.ItemsSource = null;
            settingsItemsControl.ItemsSource = _displaySettingsGroups;
            
            System.Diagnostics.Debug.WriteLine($"SettingsWindow LoadDisplaySettings: settingsItemsControl.ItemsSource обновлено. Количество групп: {_displaySettingsGroups.Count}");

            foreach (var group in _displaySettingsGroups)
            {
                foreach (var setting in group.Settings)
                {
                    System.Diagnostics.Debug.WriteLine($"SettingsWindow LoadDisplaySettings (Финальное состояние): Параметр: {setting.Parameter}, Значение: {setting.Value}, Включено: {setting.Enabled}");
                }
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("SaveButton_Click вызван!");
            
            bool oldIndividualHistorySetting = AppSettings.Instance.EnableIndividualHistorySettings;
            bool newIndividualHistorySetting = checkBoxEnableIndividualHistorySettings.IsChecked ?? true;
            
            var currentAlarmSettings = new List<AlarmSetting>();
            foreach (SettingsGroup group in _displaySettingsGroups)
            {
                foreach (AlarmSetting setting in group.Settings)
                {
                    if (setting == null) continue;
                    var newSetting = new AlarmSetting
                    {
                        Enabled = setting.Enabled,
                        Parameter = setting.Parameter,
                        Condition = setting.Condition,
                        Value = setting.Value,
                        Tab = setting.Tab,
                        Description = setting.Description
                    };
                    currentAlarmSettings.Add(newSetting);
                }
            }

            var currentYaraRules = new List<YaraRule>();
            foreach (var rule in _yaraRulesBindingList)
            {
                currentYaraRules.Add(new YaraRule
                {
                    Enabled = rule.Enabled,
                    RulePath = rule.RulePath,
                    Description = rule.Description
                });
            }
            
            if (!string.IsNullOrWhiteSpace(textBoxYaraFolderPath.Text))
            {
                var folderRules = GetYaraRulesFromFolder(textBoxYaraFolderPath.Text.Trim());
                foreach (var r in folderRules)
                {
                    if (!currentYaraRules.Any(x => x.RulePath == r.RulePath))
                        currentYaraRules.Add(r);
                }
            }
            
            if (newIndividualHistorySetting && !string.IsNullOrEmpty(mainWindow.SelectedFile))
            {
                System.Diagnostics.Debug.WriteLine($"SaveButton_Click: Индивидуальные настройки включены И выбран файл '{Path.GetFileName(mainWindow.SelectedFile)}'. Сохраняем в историю файла.");

                mainWindow.AlarmSettings.Clear();
                foreach (var setting in currentAlarmSettings)
                {
                    mainWindow.AlarmSettings.Add(setting);
                }
                mainWindow.YaraRules.Clear();
                foreach (var rule in currentYaraRules)
                {
                    mainWindow.YaraRules.Add(rule);
                }

                var existingEntry = FileHistory.Instance.GetEntryByFilePath(mainWindow.SelectedFile);
                if (existingEntry != null)
                {
                    mainWindow.UpdateFileHistoryEntrySettings(existingEntry, mainWindow.AlarmSettings, mainWindow.YaraRules);
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"SaveButton_Click: Файл '{Path.GetFileName(mainWindow.SelectedFile)}' не найден в истории, но индивидуальные настройки включены. Настройки будут применены и сохранены при первой обработке файла.");
                }

                mainWindow.SetSelectedFile(mainWindow.SelectedFile);
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("SaveButton_Click: Индивидуальные настройки выключены ИЛИ файл не выбран. Сохраняем общие настройки приложения.");

                mainWindow.AlarmSettings.Clear();
                foreach (var setting in currentAlarmSettings)
                {
                    mainWindow.AlarmSettings.Add(setting);
                }
                mainWindow.YaraRules.Clear();
                foreach (var rule in currentYaraRules)
                {
                    mainWindow.YaraRules.Add(rule);
                }
                mainWindow.UpdateGlobalAlarmSettingsFromCurrent();
                mainWindow.UpdateGlobalYaraRulesFromCurrent();
                mainWindow.UpdateCombinedYaraRules();
                mainWindow.ApplyAlarmSettings(); 

                if (!string.IsNullOrEmpty(mainWindow.SelectedFile))
                {
                    mainWindow.SetSelectedFile(mainWindow.SelectedFile);
                }
            }

            AppSettings.Instance.EnableIndividualHistorySettings = newIndividualHistorySetting;
            AppSettings.Instance.YaraFolderPath = textBoxYaraFolderPath.Text.Trim();
            AppSettings.Instance.GithubYaraPath = textBoxGithubYaraPath.Text.Trim();
            AppSettings.Instance.SaveSettings();
            
            if (oldIndividualHistorySetting != newIndividualHistorySetting)
            {
                System.Diagnostics.Debug.WriteLine($"SaveButton_Click: Настройка EnableIndividualHistorySettings изменилась с {oldIndividualHistorySetting} на {newIndividualHistorySetting}");
                mainWindow.UpdateSettingsBasedOnIndividualHistorySetting();
            }

            this.Hide();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.Hide();
        }

        private void ButtonResetToDefaults_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Вы уверены, что хотите сбросить все настройки к стандартным?\n\nЭто действие нельзя отменить.", 
                "Подтверждение сброса настроек", 
                MessageBoxButton.YesNo, 
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                AppSettings.Instance.ResetToDefaults();
                AppSettings.Instance.SaveSettings();

                LoadDisplaySettings();

                _yaraRulesBindingList = new BindingList<YaraRule>(AppSettings.Instance.GlobalYaraRules);
                yaraRulesItemsControl.ItemsSource = _yaraRulesBindingList;

                checkBoxEnableIndividualHistorySettings.IsChecked = AppSettings.Instance.EnableIndividualHistorySettings;

                mainWindow.UpdateSettingsBasedOnIndividualHistorySetting();
                MessageBox.Show("Настройки успешно сброшены к стандартным.", "Сброс настроек", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        public void ShowSettings()
        {
            LoadDisplaySettings();

            if (_yaraRulesBindingList != null)
                _yaraRulesBindingList.ListChanged -= YaraRulesBindingList_ListChanged;

            _yaraRulesBindingList = new BindingList<YaraRule>(mainWindow.YaraRules.ToList());
            _yaraRulesBindingList.ListChanged += YaraRulesBindingList_ListChanged;
            yaraRulesItemsControl.ItemsSource = null;
            yaraRulesItemsControl.ItemsSource = _yaraRulesBindingList;

            if (!string.IsNullOrEmpty(AppSettings.Instance.YaraFolderPath))
                textBoxYaraFolderPath.Text = AppSettings.Instance.YaraFolderPath;
            if (!string.IsNullOrEmpty(AppSettings.Instance.GithubYaraPath))
                textBoxGithubYaraPath.Text = AppSettings.Instance.GithubYaraPath;

            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            this.ShowDialog();
        }

        private void YaraRulesBindingList_ListChanged(object sender, ListChangedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("YaraRulesBindingList_ListChanged вызван! Тип: " + e.ListChangedType);
            if (e.ListChangedType == ListChangedType.ItemChanged)
            {
                ApplySettingsImmediately();
            }
        }

        private void SettingsWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            e.Cancel = true;
            this.Hide();
        }

        private void AddYaraRule_Click(object sender, RoutedEventArgs e)
        {
            var rule = new YaraRule { Enabled = true, RulePath = "", Description = "" };
            _yaraRulesBindingList.Add(rule);
            UpdateYaraRulesSource();
            ApplySettingsImmediately();
        }

        private void DeleteYaraRule_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                YaraRule rule = null;
                if (sender is Button btn)
                {
                    rule = btn.DataContext as YaraRule;
                    btn.MoveFocus(new System.Windows.Input.TraversalRequest(System.Windows.Input.FocusNavigationDirection.Next));
                }
                if (rule != null && _yaraRulesBindingList.Contains(rule))
                {
                    _yaraRulesBindingList.Remove(rule);
                    UpdateYaraRulesSource();
                    ApplySettingsImmediately();
                    yaraRulesItemsControl.ItemsSource = null;
                    yaraRulesItemsControl.ItemsSource = _yaraRulesBindingList;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при удалении YARA-правила: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SelectYaraFile_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is YaraRule rule)
            {
                var ofd = new Microsoft.Win32.OpenFileDialog();
                ofd.Filter = "YARA-файлы (*.yar;*.yara;*.txt)|*.yar;*.yara;*.txt|Все файлы (*.*)|*.*";
                if (ofd.ShowDialog() == true)
                {
                    rule.RulePath = ofd.FileName;
                    rule.Description = System.IO.Path.GetFileName(ofd.FileName);
                    int idx = _yaraRulesBindingList.IndexOf(rule);
                    if (idx >= 0 && idx < _yaraRulesBindingList.Count)
                    {
                        _yaraRulesBindingList.ResetItem(idx);
                    }
                    UpdateYaraRulesSource();
                    ApplySettingsImmediately();
                }
            }
        }

        private void UpdateYaraRulesSource()
        {
            var list = _yaraRulesBindingList.ToList();
            YaraSettings.Instance.Rules = list;
            mainWindow.YaraRules = list;
        }

        private void ApplySettingsImmediately()
        {
            System.Diagnostics.Debug.WriteLine("ApplySettingsImmediately вызван!");

            var currentAlarmSettings = new List<AlarmSetting>();
            foreach (SettingsGroup group in _displaySettingsGroups)
            {
                foreach (AlarmSetting setting in group.Settings)
                {
                    if (setting == null) continue;
                    var newSetting = new AlarmSetting
                    {
                        Enabled = setting.Enabled,
                        Parameter = setting.Parameter,
                        Condition = setting.Condition,
                        Value = setting.Value,
                        Tab = setting.Tab,
                        Description = setting.Description
                    };
                    currentAlarmSettings.Add(newSetting);
                }
            }

            var currentYaraRules = new List<YaraRule>();
            foreach (var rule in _yaraRulesBindingList)
            {
                currentYaraRules.Add(new YaraRule
                {
                    Enabled = rule.Enabled,
                    RulePath = rule.RulePath,
                    Description = rule.Description
                });
            }
            
            if (AppSettings.Instance.EnableIndividualHistorySettings && !string.IsNullOrEmpty(mainWindow.SelectedFile))
            {
                System.Diagnostics.Debug.WriteLine($"ApplySettingsImmediately: Индивидуальные настройки включены И выбран файл '{Path.GetFileName(mainWindow.SelectedFile)}'. Сохраняем в историю файла.");

                mainWindow.AlarmSettings.Clear();
                foreach (var setting in currentAlarmSettings)
                {
                    mainWindow.AlarmSettings.Add(setting);
                }
                mainWindow.YaraRules.Clear();
                foreach (var rule in currentYaraRules)
                {
                    mainWindow.YaraRules.Add(rule);
                }

                var existingEntry = FileHistory.Instance.GetEntryByFilePath(mainWindow.SelectedFile);
                if (existingEntry != null)
                {
                    mainWindow.UpdateFileHistoryEntrySettings(existingEntry, mainWindow.AlarmSettings, mainWindow.YaraRules);
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"ApplySettingsImmediately: Файл '{Path.GetFileName(mainWindow.SelectedFile)}' не найден в истории, но индивидуальные настройки включены. Настройки будут применены и сохранены при первой обработке файла.");
                }

                mainWindow.Dispatcher.BeginInvoke(new Action(() =>
                {
                    mainWindow.SetSelectedFile(mainWindow.SelectedFile);
                    mainWindow.SetControlsEnabled(!string.IsNullOrEmpty(mainWindow.SelectedFile));
                    mainWindow.UpdateLayout();
                }));

            }
            else
            {
                System.Diagnostics.Debug.WriteLine("ApplySettingsImmediately: Индивидуальные настройки выключены ИЛИ файл не выбран. Сохраняем общие настройки приложения.");

                mainWindow.AlarmSettings.Clear();
                foreach (var setting in currentAlarmSettings)
                {
                    mainWindow.AlarmSettings.Add(setting);
                }
                mainWindow.YaraRules.Clear();
                foreach (var rule in currentYaraRules)
                {
                    mainWindow.YaraRules.Add(rule);
                }
                mainWindow.UpdateGlobalAlarmSettingsFromCurrent();
                mainWindow.UpdateGlobalYaraRulesFromCurrent();
                mainWindow.UpdateCombinedYaraRules();
                mainWindow.ApplyAlarmSettings();

                if (!string.IsNullOrEmpty(mainWindow.SelectedFile))
                {
                    mainWindow.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        mainWindow.SetSelectedFile(mainWindow.SelectedFile);
                        mainWindow.SetControlsEnabled(!string.IsNullOrEmpty(mainWindow.SelectedFile));
                        mainWindow.UpdateLayout();
                    }));
                }
                else
                {
                     mainWindow.SetControlsEnabled(!string.IsNullOrEmpty(mainWindow.SelectedFile));
                     mainWindow.UpdateLayout();
                }
            }
        }

        private void AlarmSetting_Checked(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("AlarmSetting_Checked вызван!");
            ApplySettingsImmediately();
        }

        private void AlarmSetting_Unchecked(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("AlarmSetting_Unchecked вызван!");
            ApplySettingsImmediately();
        }

        private void AlarmSetting_TextChanged(object sender, TextChangedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("AlarmSetting_TextChanged вызван!");
            ApplySettingsImmediately();
        }

        private void AlarmSetting_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("AlarmSetting_SelectionChanged вызван!");
            ApplySettingsImmediately();
        }

        private void CheckBoxEnableIndividualHistorySettings_Changed(object sender, RoutedEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("CheckBoxEnableIndividualHistorySettings_Changed вызван!");
            ApplySettingsImmediately();
        }

        private async void BrowseYaraFolder_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.Title = "Выберите папку с YARA-правилами";
            dlg.Filter = "Папки|*.none";
            dlg.ValidateNames = false;
            dlg.CheckFileExists = false;
            dlg.CheckPathExists = true;
            dlg.FileName = "Выберите папку";
            if (dlg.ShowDialog() == true)
            {
                string folder = System.IO.Path.GetDirectoryName(dlg.FileName);
                textBoxYaraFolderPath.Text = folder;
                if (!string.IsNullOrWhiteSpace(folder))
                {
                    SetYaraUiEnabled(false);
                    labelYaraLoading.Content = "Загрузка правил...";
                    var rules = await Task.Run(() => GetYaraRulesFromFolder(folder));
                    foreach (var r in rules)
                    {
                        if (!_yaraRulesBindingList.Any(x => x.RulePath == r.RulePath))
                            _yaraRulesBindingList.Add(r);
                    }
                    UpdateYaraRulesSource();
                    ApplySettingsImmediately();
                    labelYaraLoading.Content = "";
                    SetYaraUiEnabled(true);
                }
            }
        }

        private void SetYaraUiEnabled(bool enabled)
        {
            textBoxYaraFolderPath.IsEnabled = enabled;
            textBoxGithubYaraPath.IsEnabled = enabled;
            // Добавьте сюда все кнопки, связанные с YARA (Обзор, Очистить, Загрузить, Удалить все правила)
            // Например:
            // buttonBrowseYaraFolder.IsEnabled = enabled;
            // buttonClearYaraFolder.IsEnabled = enabled;
            // buttonDownloadGithubYara.IsEnabled = enabled;
            // buttonClearGithubYara.IsEnabled = enabled;
            // buttonDeleteAllYaraRules.IsEnabled = enabled;
        }

        private void DownloadYaraFromGithub_Click(object sender, RoutedEventArgs e)
        {
            string repoOrFolder = textBoxGithubYaraPath.Text.Trim();
            if (!string.IsNullOrEmpty(repoOrFolder))
            {
                var result = MessageBox.Show($"Загрузить YARA-правила из:\n{repoOrFolder}?", "Загрузка YARA-правил", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    var rules = GetYaraRulesFromGithub(repoOrFolder);
                    foreach (var r in rules)
                    {
                        if (!_yaraRulesBindingList.Any(x => x.RulePath == r.RulePath))
                            _yaraRulesBindingList.Add(r);
                    }
                    UpdateYaraRulesSource();
                    ApplySettingsImmediately();
                }
                else
                {
                    MessageBox.Show("Загрузка отменена.", "Отмена", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        private List<YaraRule> GetYaraRulesFromFolder(string folderPath)
        {
            var rules = new List<YaraRule>();
            int total = 0, success = 0, failed = 0;
            if (!Directory.Exists(folderPath)) return rules;
            var files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase));
            foreach (var file in files)
            {
                total++;
                try
                {
                    rules.Add(new YaraRule
                    {
                        Enabled = true,
                        RulePath = file,
                        Description = Path.GetFileName(file)
                    });
                    success++;
                }
                catch { failed++; }
            }
            return rules;
        }
 
        private List<YaraRule> GetYaraRulesFromGithub(string url)
        {
            var rules = new List<YaraRule>();
            string lastSearchRoot = null;
            try
            {
                string repoUrl = url.TrimEnd('/');
                string branch = "main";
                string subdir = "";
                if (repoUrl.Contains("/tree/"))
                {
                    var parts = repoUrl.Split(new string[] { "/tree/" }, StringSplitOptions.None);
                    repoUrl = parts[0];
                    var branchAndSub = parts[1].Split(new char[] {'/'}, 2);
                    branch = branchAndSub[0];
                    if (branchAndSub.Length > 1) subdir = branchAndSub[1];
                }
                else if (repoUrl.Contains("/blob/"))
                {
                    repoUrl = repoUrl.Substring(0, repoUrl.IndexOf("/blob/"));
                }
                string cacheRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "YaraGithubCache");
                Directory.CreateDirectory(cacheRoot);
                string repoName = repoUrl.Split('/').Last();
                string extractDir = Path.Combine(cacheRoot, repoName + "_unpacked");
                if (Directory.Exists(extractDir)) Directory.Delete(extractDir, true);
                string[] branchesToTry = new[] { "main", "master" };
                bool success = false;
                foreach (var tryBranch in branchesToTry)
                {
                    string archiveUrl = repoUrl.Replace("github.com", "github.com").Replace(".git", "") + $"/archive/refs/heads/{tryBranch}.zip";
                    string tempZip = Path.Combine(cacheRoot, repoName + $"_{tryBranch}.zip");
                    try
                    {
                        using (var client = new WebClient())
                        {
                            client.DownloadFile(archiveUrl, tempZip);
                        }
                        ZipFile.ExtractToDirectory(tempZip, extractDir);
                        File.Delete(tempZip);
                        string root = Directory.GetDirectories(extractDir).FirstOrDefault() ?? extractDir;
                        string searchRoot = string.IsNullOrEmpty(subdir) ? root : Path.Combine(root, subdir);
                        lastSearchRoot = searchRoot;
                        if (Directory.Exists(searchRoot))
                        {
                            var folderRules = GetYaraRulesFromFolder(searchRoot);
                            rules.AddRange(folderRules);
                            success = true;
                            break;
                        }
                    }
                    catch (WebException ex)
                    {
                        if (ex.Response is HttpWebResponse resp && (int)resp.StatusCode == 404)
                        {
                            continue;
                        }
                        else
                        {
                            MessageBox.Show($"Ошибка загрузки YARA-правил из GitHub: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Ошибка загрузки YARA-правил из GitHub: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                        break;
                    }
                }
                if (!success)
                {
                    MessageBox.Show($"Не удалось скачать архив ни с ветки 'main', ни с 'master'. Проверьте ссылку или ветки репозитория.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка загрузки YARA-правил из GitHub: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            if (rules.Count > 0 && !string.IsNullOrEmpty(lastSearchRoot))
            {
                _lastGithubYaraFolder = lastSearchRoot;
            }
            return rules;
        }

        private void ClearYaraFolderPath_Click(object sender, RoutedEventArgs e)
        {
            textBoxYaraFolderPath.Text = string.Empty;
        }

        private void ClearGithubYaraPath_Click(object sender, RoutedEventArgs e)
        {
            textBoxGithubYaraPath.Text = string.Empty;
        }

        private void DeleteAllYaraRules_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Удалить все YARA-правила?", "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
            {
                _yaraRulesBindingList.Clear();
                UpdateYaraRulesSource();
                ApplySettingsImmediately();
            }
        }
    }

    public class SettingsGroup
    {
        public string GroupName { get; set; }
        public List<AlarmSetting> Settings { get; set; }
    }

    public class AlarmSetting : INotifyPropertyChanged
    {
        private bool _enabled;
        private string _value;

        public bool Enabled
        {
            get => _enabled;
            set
            {
                if (_enabled != value)
                {
                    _enabled = value;
                    OnPropertyChanged();
                }
            }
        }
        public string Parameter { get; set; }
        public string Condition { get; set; }
        public string Value
        {
            get => _value;
            set
            {
                if (_value != value)
                {
                    _value = value;
                    OnPropertyChanged();
                }
            }
        }
        public string Tab { get; set; }
        public string Description { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }





        public bool CheckAlarm(string value)
        {
            switch (Condition)
            {
                case "Не 'Signed'":
                    return !value.Equals("Signed", StringComparison.OrdinalIgnoreCase);

                case "Дата <":
                    DateTime fileDate;
                    if (DateTime.TryParse(value, out fileDate))
                    {
                    }
                    else
                    {
                        var match = System.Text.RegularExpressions.Regex.Match(value, @"(\d{1,2}):(\d{1,2})\s+(\d{1,2})\.(\d{1,2})\.(\d{4})");
                        if (match.Success)
                        {
                            try
                            {
                                int hour = int.Parse(match.Groups[1].Value);
                                int minute = int.Parse(match.Groups[2].Value);
                                int day = int.Parse(match.Groups[3].Value);
                                int month = int.Parse(match.Groups[4].Value);
                                int year = int.Parse(match.Groups[5].Value);
                                fileDate = new DateTime(year, month, day, hour, minute, 0);
                            }
                            catch
                            {
                                return true;
                            }
                        }
                        else
                        {
                            return true;
                        }
                    }

                    DateTime thresholdDate;
                    if (DateTime.TryParse(Value, out thresholdDate))
                    {
                        return fileDate < thresholdDate;
                    }
                    else
                    {
                        return true;
                    }

                case ">":
                    if (Parameter == "VT detection")
                    {
                        if (value.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                            return true;
                        
                        var vtMatch = System.Text.RegularExpressions.Regex.Match(value, @"^(\d+)");
                        if (vtMatch.Success && int.TryParse(vtMatch.Groups[1].Value, out int vtValue) && int.TryParse(Value, out int threshold))
                        {
                            return vtValue > threshold;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    else if (Parameter == "Entropy" || Parameter == "Энтропия секций" || Parameter == "Общая энтропия файла")
                    {
                        if (double.TryParse(value.Replace(",", "."), System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out double entropyValue) &&
                            double.TryParse(Value.Replace(",", "."), System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out double threshold))
                            return entropyValue > threshold;
                        else
                            return false;
                    }
                    return false;

                case "Версия <":
                    int dotsInFileVersion = value.Count(c => c == '.');
                    
                    string thresholdValue = Value;
                    if (Value.Contains(":"))
                    {
                        thresholdValue = Value.Split(':')[1].Trim();
                    }
                    
                    int dotsInThreshold = thresholdValue.Count(c => c == '.');
                    
                    if (dotsInFileVersion > dotsInThreshold)
                    {
                        return true;
                    }

                    return false;

                case "Содержит":
                    return value.IndexOf(Value, StringComparison.OrdinalIgnoreCase) >= 0;

                default:
                    return false;
            }
        }
    }
}




