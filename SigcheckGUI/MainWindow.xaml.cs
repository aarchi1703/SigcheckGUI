using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using static System.Windows.Clipboard;
using System.Windows.Navigation;

namespace SigcheckGUI
{
    public partial class MainWindow : Window
    {
        private SettingsWindow settingsWindow;
        private string selectedFile = null;
        private System.Windows.Threading.DispatcherTimer _vtLoadingTimer;
        private int _vtLoadingDotsCount;
        private Dictionary<int, string> fullVtLinks = new Dictionary<int, string>();
        private const int MAX_VT_ATTEMPTS = 12;
        private int vtAttempts;
        public List<AlarmSetting> AlarmSettings { get; private set; } = new List<AlarmSetting>();

        private List<YaraRule> _yaraRules = new List<YaraRule>();
        public List<YaraRule> YaraRules { get; set; } = new List<YaraRule>();

        private RichTextBox historyRichTextBox;
        private bool _isRestoringHistory = false;

        private System.Windows.Threading.DispatcherTimer _alarmLoadingTimer;
        private int _alarmLoadingDotsCount;

        public string SelectedFile => selectedFile;

        public void SetSelectedFile(string filePath)
        {
            this._selectedFile = filePath;
        }

        private string _selectedFile
        {
            get => selectedFile;
            set
            {
                System.Diagnostics.Debug.WriteLine($"_selectedFile setter: Value = '{value ?? "null"}'");
                if (selectedFile != value)
                {
                    selectedFile = value;
                    if (!string.IsNullOrEmpty(selectedFile))
                    {
                        labelSelectedFile.Text = selectedFile;
                        SetControlsEnabled(true);
                        
                        var existingEntry = FileHistory.Instance.GetEntryByFilePath(selectedFile);
                        bool fileWasProcessedBefore = existingEntry != null;
                        bool individualSettingsEnabled = AppSettings.Instance.EnableIndividualHistorySettings;
                        
                        System.Diagnostics.Debug.WriteLine($"SelectedFile: Файл {Path.GetFileName(selectedFile)} был обработан ранее: {fileWasProcessedBefore}");
                        System.Diagnostics.Debug.WriteLine($"SelectedFile: Индивидуальные настройки включены: {individualSettingsEnabled}");
                        
                        if (fileWasProcessedBefore)
                        {
                            System.Diagnostics.Debug.WriteLine($"SelectedFile: Найдена запись в истории для файла {Path.GetFileName(selectedFile)}");
                            System.Diagnostics.Debug.WriteLine($"SelectedFile: В истории сохранено алармов: {existingEntry.AppliedAlarmSettings.Count}");
                            System.Diagnostics.Debug.WriteLine($"SelectedFile: В истории сохранено YARA правил: {existingEntry.AppliedYaraRules.Count}");
                        }
                        
                        if (individualSettingsEnabled)
                        {

                            if (fileWasProcessedBefore)
                            {

                                System.Diagnostics.Debug.WriteLine($"SelectedFile: Применяем индивидуальные настройки для файла {Path.GetFileName(selectedFile)}");
                                
                                AlarmSettings.Clear();
                                foreach (var setting in existingEntry.AppliedAlarmSettings)
                                {
                                    AlarmSettings.Add(setting);
                                }
                                _yaraRules.Clear();
                                foreach (var rule in existingEntry.AppliedYaraRules)
                                {
                                    _yaraRules.Add(rule);
                                }
                                YaraRules.Clear();
                                foreach (var rule in _yaraRules)
                                {
                                    YaraRules.Add(rule);
                                }
                                
                                System.Diagnostics.Debug.WriteLine($"SelectedFile: Загружено {AlarmSettings.Count} индивидуальных алармов и {YaraRules.Count} YARA правил");
                                

                                foreach (var alarm in AlarmSettings)
                                {
                                    System.Diagnostics.Debug.WriteLine($"SelectedFile: Загружен аларм: {alarm.Parameter} = {alarm.Value} (Enabled: {alarm.Enabled})");
                                }
                            }
                            else
                            {

                                System.Diagnostics.Debug.WriteLine($"SelectedFile: Файл {Path.GetFileName(selectedFile)} новый, применяем стандартные настройки");
                                

                                AlarmSettings.Clear();
                                foreach (var setting in GetDefaultAlarmSettings())
                                {
                                    AlarmSettings.Add(setting);
                                }
                                _yaraRules.Clear();
                                foreach (var rule in GetDefaultYaraRules())
                                {
                                    _yaraRules.Add(rule);
                                }
                                YaraRules.Clear();
                                foreach (var rule in _yaraRules)
                                {
                                    YaraRules.Add(rule);
                                }
                                

                                System.Diagnostics.Debug.WriteLine($"SelectedFile: Загружено {AlarmSettings.Count} стандартных алармов и {YaraRules.Count} YARA правил");
                                
                                foreach (var alarm in AlarmSettings)
                                {
                                    System.Diagnostics.Debug.WriteLine($"SelectedFile: Загружен стандартный аларм: {alarm.Parameter} = {alarm.Value} (Enabled: {alarm.Enabled})");
                                }
                            }
                        }
                        else
                        {

                            System.Diagnostics.Debug.WriteLine($"SelectedFile: Индивидуальные настройки выключены, применяем общие настройки для файла {Path.GetFileName(selectedFile)}");
                            
                            LoadAlarmSettings();
                            LoadYaraRules();
                            
                            System.Diagnostics.Debug.WriteLine($"SelectedFile: Загружено {AlarmSettings.Count} общих алармов и {YaraRules.Count} YARA правил");
                        }
                        
                        if (!_isRestoringHistory)
                        {
                            RunSigcheckAll();
                            
                            ApplyAlarmSettings();
                            if (YaraRules.Any(r => r.Enabled && File.Exists(r.RulePath)))
                            {
                                System.Diagnostics.Debug.WriteLine("SelectedFile: Автоматически запускаем YARA-сканирование для нового/выбранного файла");
                                Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                                {
                                    RunYaraScan();
                                }));
                            }
                            

                            StringBuilder info = new StringBuilder();
                            info.AppendLine($"=== ИНФОРМАЦИЯ О НАСТРОЙКАХ ДЛЯ ФАЙЛА {Path.GetFileName(selectedFile)} ===");
                            info.AppendLine($"Файл был обработан ранее: {fileWasProcessedBefore}");
                            info.AppendLine($"Индивидуальные настройки включены: {individualSettingsEnabled}");
                            info.AppendLine($"Применено алармов: {AlarmSettings.Count}");
                            info.AppendLine($"Применено YARA правил: {YaraRules.Count}");
                            
                            if (individualSettingsEnabled && fileWasProcessedBefore)
                            {
                                info.AppendLine("ТИП НАСТРОЕК: Индивидуальные настройки файла из истории");
                                info.AppendLine($"Источник: История файла {Path.GetFileName(selectedFile)}");
                            }
                            else if (individualSettingsEnabled && !fileWasProcessedBefore)
                            {
                                info.AppendLine("ТИП НАСТРОЕК: Стандартные настройки (файл новый)");
                                info.AppendLine("Источник: Встроенные стандартные настройки приложения");
                            }
                            else
                            {
                                info.AppendLine("ТИП НАСТРОЕК: Общие настройки приложения");
                                info.AppendLine("Источник: Глобальные настройки AppSettings");
                            }
                            
                            info.AppendLine();
                            info.AppendLine("=== ПРИМЕНЕННЫЕ АЛАРМЫ ===");
                            foreach (var alarm in AlarmSettings)
                            {
                                info.AppendLine($"• {alarm.Parameter}: {alarm.Condition} {alarm.Value} (Enabled: {alarm.Enabled})");
                            }
                            
                            info.AppendLine();
                            info.AppendLine("=== ПРИМЕНЕННЫЕ YARA ПРАВИЛА ===");
                            if (YaraRules.Count > 0)
                            {
                                foreach (var rule in YaraRules)
                                {
                                    info.AppendLine($"• {rule.Description}: {rule.RulePath} (Enabled: {rule.Enabled})");
                                }
                            }
                            else
                            {
                                info.AppendLine("Нет примененных YARA правил");
                            }
                            
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine("SelectedFile: Восстановление из истории - пропускаем RunSigcheckAll и автоматическое применение настроек");
                        }
                    }
                    else
                    {
                        labelSelectedFile.Text = "Файл не выбран";
                        SetControlsEnabled(false);
                        SetTabText(7, "");
                        SetTabText(8, "");
                        SetTabText(9, "");
                    }
                }
            }
        }

        public MainWindow()
        {
            InitializeComponent();
            
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            
            FileHistory.Instance.CleanupDuplicateEntries();
            
            LoadGlobalSettings();
            InitializeUI();
            SetTabText(7, "");
            SetTabText(8, "");
            SetTabText(9, "");
            ApplyAlarmSettings();
            settingsWindow = new SettingsWindow(this);
            InitializeLoadingTimer();
            this.Closed += MainWindow_Closed;

            foreach (TabItem tab in tabControlResults.Items)
            {
                if (tab.Content is RichTextBox rtb)
                {
                    rtb.AddHandler(Hyperlink.RequestNavigateEvent, new RequestNavigateEventHandler(Hyperlink_RequestNavigate));
                }
            }
        }

        private void LoadGlobalSettings()
        {
            System.Diagnostics.Debug.WriteLine("LoadGlobalSettings: Загрузка всех глобальных настроек приложения...");
            LoadAlarmSettings();
            LoadYaraRules();
            AppSettings.Instance.SaveSettings();
            System.Diagnostics.Debug.WriteLine("LoadGlobalSettings: Глобальные настройки загружены и сохранены (если были пусты).");
        }

        private void LoadYaraRules()
        {
            System.Diagnostics.Debug.WriteLine("LoadYaraRules: Загрузка глобальных правил YARA из AppSettings...");
            if (!AppSettings.Instance.GlobalYaraRules.Any())
            {
                System.Diagnostics.Debug.WriteLine("LoadYaraRules: Глобальные правила YARA пусты, загружаем дефолтные (пустые).");
                AppSettings.Instance.GlobalYaraRules = GetDefaultYaraRules();
                AppSettings.Instance.SaveSettings();
            }

            _yaraRules.Clear();
            foreach (var rule in AppSettings.Instance.GlobalYaraRules)
            {
                _yaraRules.Add(rule);
            }
            YaraRules.Clear();
            foreach (var rule in _yaraRules)
            {
                YaraRules.Add(rule);
            }
            
            if (_yaraRules.Any(r => r.Enabled && File.Exists(r.RulePath)))
            {
                System.Diagnostics.Debug.WriteLine("LoadYaraRules: Найдены активные YARA правила, применяем их...");
                ApplyYaraRulesOnStartup();
            }
            System.Diagnostics.Debug.WriteLine($"LoadYaraRules: Загружено {YaraRules.Count} глобальных правил YARA.");
        }

        public void SaveYaraRulesAndApply()
        {
            System.Diagnostics.Debug.WriteLine("SaveYaraRulesAndApply: Применение текущих правил YARA к UI и обновление объединенного файла.");
            YaraRules = new List<YaraRule>(_yaraRules);
            
            UpdateCombinedYaraRules();
            
            ApplyAlarmSettings();
            System.Diagnostics.Debug.WriteLine($"SaveYaraRulesAndApply: Применено {YaraRules.Count} правил YARA.");
        }

        public void SaveAlarmSettingsAndApply()
        {
            System.Diagnostics.Debug.WriteLine("SaveAlarmSettingsAndApply: Применение текущих настроек тревог к UI.");
            ApplyAlarmSettings();
        }

        private static readonly Dictionary<string, string> sigcheckRuDict = new Dictionary<string, string>
        {
            { "Verified:", "Подпись:" },
            { "Unsigned", "Не подписан" },
            { "Signed", "Подписан" },
            { "Publisher:", "Издатель:" },
            { "Company:", "Компания:" },
            { "Description:", "Описание:" },
            { "Product:", "Продукт:" },
            { "File version:", "Версия файла:" },
            { "Prod version:", "Версия продукта:" },
            { "Original Name:", "Оригинальное имя:" },
            { "Internal Name:", "Внутреннее имя:" },
            { "Copyright:", "Авторские права:" },
            { "Comments:", "Комментарии:" },
            { "Entropy:", "Энтропия:" },
            { "Link date:", "Дата компиляции:" },
            { "MachineType:", "Тип процессора:" },
            { "Binary Version:", "Версия бинарника:" },
            { "MD5:", "MD5:" },
            { "SHA1:", "SHA1:" },
            { "PESHA1:", "PESHA1:" },
            { "PE256:", "PE256:" },
            { "SHA256:", "SHA256:\"" },
            { "IMP:", "IMP:" },
            { "VT detection:", "Обнаружение VirusTotal:" },
            { "VT link:", "Ссылка VirusTotal:" },
            { "No matching files were found.", "Каталожный файл не найден или совпадений нет." }
        };

        private void MainWindow_Closed(object sender, EventArgs e)
        {
            _vtLoadingTimer.Stop();
            settingsWindow?.Close();
            Environment.Exit(0);
        }

        private void InitializeUI()
        {
            this.AllowDrop = true;
            this.Drop += MainWindow_Drop;
            this.DragOver += MainWindow_DragOver;
            SetControlsEnabled(false);
            InitializeTabs();
            SetupToolTips();
        }

        private void RichTextBox_PreviewDragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void RichTextBox_PreviewDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    SetSelectedFile(files[0]);
                }
            }
        }

        private void InitializeLoadingTimer()
        {
            _vtLoadingTimer = new System.Windows.Threading.DispatcherTimer();
            _vtLoadingTimer.Interval = TimeSpan.FromMilliseconds(500);
            _vtLoadingTimer.Tick += LoadingTimer_Tick;
        }

        private void LoadingTimer_Tick(object sender, EventArgs e)
        {
            _vtLoadingDotsCount = (_vtLoadingDotsCount + 1) % 4;
            string dots = new string('.', _vtLoadingDotsCount);
            string spaces = new string(' ', 3 - _vtLoadingDotsCount);
            SetTabText(5, $"Проверка VirusTotal выполняется{dots}{spaces}\nПожалуйста, подождите...");
        }

        private void SetupToolTips()
        {
            ToolTipService.SetToolTip(checkBoxRParam, "Рекурсивная проверка сертификатов\nПроверяет все сертификаты в цепочке");
            ToolTipService.SetToolTip(checkBoxSParam, "Проверка отзыва сертификатов\nПроверяет статус отзыва через интернет");
        }

        private void InitializeTabs()
        {
            tabControlResults.Items.Clear();
            string[] tabNames = {
                "All Info (-a)",
                "Catalog Content (-d)",
                "Hashes (-h)",
                "Manifest (-m)",
                "Version Number (-n)",
                "VirusTotal (-v)",
                "Энтропия",
                "YARA",
            };
            foreach (string name in tabNames)
            {
                TabItem tab = new TabItem { Header = name };
                RichTextBox rtb = new RichTextBox
                {
                    IsDocumentEnabled = true,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    VerticalAlignment = VerticalAlignment.Stretch,
                    Margin = new Thickness(5),
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                };

                rtb.PreviewDragOver += RichTextBox_PreviewDragOver;
                rtb.PreviewDrop += RichTextBox_PreviewDrop;

                if (name == "VirusTotal (-v)")
                {
                    rtb.MouseLeftButtonUp += rtbVirusTotal_MouseLeftButtonUp;
                }

                if (name == "История")
                {
                    historyRichTextBox = rtb;
                    historyRichTextBox.IsReadOnly = true;
                    historyRichTextBox.IsDocumentEnabled = true;
                    historyRichTextBox.SelectionBrush = Brushes.Transparent;
                    historyRichTextBox.AcceptsReturn = false;
                    historyRichTextBox.AcceptsTab = false;
                    historyRichTextBox.Background = Brushes.White;
                    historyRichTextBox.Foreground = Brushes.Black;
                    historyRichTextBox.BorderThickness = new Thickness(0);
                    historyRichTextBox.FontFamily = new FontFamily("Consolas");
                    historyRichTextBox.FontSize = 12;
                    historyRichTextBox.HorizontalScrollBarVisibility = ScrollBarVisibility.Auto;
                    historyRichTextBox.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
                }
                tab.Content = rtb;
                tabControlResults.Items.Add(tab);
            }

            if (!tabNames.Contains("История"))
            {
                TabItem historyTab = new TabItem { Header = "История" };
                RichTextBox historyRtb = new RichTextBox
                {
                    IsDocumentEnabled = true,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    VerticalAlignment = VerticalAlignment.Stretch,
                    Margin = new Thickness(5),
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    IsReadOnly = true,
                    SelectionBrush = Brushes.Transparent,
                    AcceptsReturn = false,
                    AcceptsTab = false,
                    Background = Brushes.White,
                    Foreground = Brushes.Black,
                    BorderThickness = new Thickness(0),
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                };
                historyRichTextBox = historyRtb;
                historyTab.Content = historyRtb;
                tabControlResults.Items.Add(historyTab);
            }
        }

        public void SetControlsEnabled(bool enabled)
        {
            buttonRefresh.IsEnabled = enabled;
            buttonSaveReport.IsEnabled = enabled;
            buttonSaveReportRu.IsEnabled = enabled;
            buttonSettings.IsEnabled = enabled;
            checkBoxRParam.IsEnabled = enabled;
            checkBoxSParam.IsEnabled = enabled;
        }

        private string GetSigcheckPath()
        {

                string tempFolderPath = Path.GetTempPath();
                string tempExePath = Path.Combine(tempFolderPath, "sigcheck.exe");

                if (File.Exists(tempExePath))
                    {
                        return tempExePath;
                }

                byte[] exeBytes;
                string resourceName = "SigcheckGUI.sigcheck.exe";
                using (System.IO.Stream stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                    {
                        throw new InvalidOperationException($"Встроенный ресурс '{resourceName}' не найден. Убедитесь, что 'sigcheck.exe' добавлен как встроенный ресурс с правильным именем.");
                    }
                    exeBytes = new byte[stream.Length];
                    stream.Read(exeBytes, 0, (int)stream.Length);
                }

                File.WriteAllBytes(tempExePath, exeBytes);
                return tempExePath;
            }


        private string GetYaraPath()
        {

                string tempFolderPath = Path.GetTempPath();
                string tempExePath = Path.Combine(tempFolderPath, "yara64.exe");

                if (File.Exists(tempExePath))
                {
                    return tempExePath;
                }

                byte[] exeBytes;
                string resourceName = "SigcheckGUI.yara64.exe";
                using (System.IO.Stream stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                    {
                        throw new InvalidOperationException($"Встроенный ресурс '{resourceName}' не найден. Убедитесь, что 'yara64.exe' добавлен как встроенный ресурс с правильным именем.");
                    }
                    exeBytes = new byte[stream.Length];
                    stream.Read(exeBytes, 0, (int)stream.Length);
                }

                File.WriteAllBytes(tempExePath, exeBytes);
                return tempExePath;
            }


        private void MainWindow_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void MainWindow_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    SetSelectedFile(files[0]);
                }
            }
        }

        private void ButtonSelectFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                SetSelectedFile(ofd.FileName);
            }
            else
            {
                SetSelectedFile(null);
            }
        }

        public void RunSigcheckAll()
        {
            if (string.IsNullOrEmpty(selectedFile)) return;
            if (!File.Exists(selectedFile))
            {
                MessageBox.Show("Выберите корректный файл.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            
            string sigcheckPath = GetSigcheckPath();
            if (!File.Exists(sigcheckPath))
            {
                MessageBox.Show($"Не найден файл sigcheck.exe по пути:\n{sigcheckPath}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            string[] flags = { "-a", "-d", "-h", "-m", "-n" };
            for (int i = 0; i < flags.Length; i++)
            {
                RunSigcheckAndDisplay($"-nobanner {flags[i]} \"{selectedFile}\"", i);
            }
            RunVirusTotalCheck();
            CalculateAndDisplayEntropy();
            
            ApplyAlarmSettings();
            RunYaraScan();
            
            SaveFileHistory();
        }

        private void RunSigcheckAndDisplay(string arguments, int tabIndex)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = GetSigcheckPath(),
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                    WorkingDirectory = System.AppDomain.CurrentDomain.BaseDirectory
                };

                using (Process proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    string error = proc.StandardError.ReadToEnd();
                    proc.WaitForExit();

                    if (!string.IsNullOrEmpty(error))
                    {
                        SetTabText(tabIndex, $"Ошибка sigcheck:\n{error}");
                        return;
                    }

                    if (arguments.Contains("-d") && string.IsNullOrWhiteSpace(output))
                        output = sigcheckRuDict["No matching files were found."];

                    if (arguments.Contains("-m"))
                        output = FormatXmlOutput(output);

                    SetTabText(tabIndex, output);
                }
            }
            catch (Exception ex)
            {
                SetTabText(tabIndex, $"Ошибка sigcheck:\n{ex.Message}");
            }
        }

        private async Task<string> RunSigcheckAsync(string arguments)
        {
            return await Task.Run(() =>
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = GetSigcheckPath(),
                        Arguments = arguments,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.UTF8,
                        StandardErrorEncoding = Encoding.UTF8,
                        WorkingDirectory = System.AppDomain.CurrentDomain.BaseDirectory
                    };

                    using (Process proc = new Process())
                    {
                        proc.StartInfo = psi;
                        proc.Start();

                        if (!proc.WaitForExit(30000)) 
                        {
                            proc.Kill();
                            return "Ошибка: Процесс sigcheck.exe превысил время ожидания (4 секунды).";
                        }

                        string output = proc.StandardOutput.ReadToEnd();
                        string error = proc.StandardError.ReadToEnd();

                        if (!string.IsNullOrEmpty(error))
                        {
                            return $"Ошибка sigcheck:\n{error}";
                        } 

                        return output;
                    }
                }
                catch (Exception ex)
                {
                    return $"Ошибка sigcheck:\n{ex.Message}";
                }
            });
        }

        private string FormatXmlOutput(string output)
        {
            try
            {
                int xmlStart = output.IndexOf("<?xml");
                if (xmlStart < 0) return output;

                string beforeXml = output.Substring(0, xmlStart);
                string xmlPart = output.Substring(xmlStart);

                if (xmlPart.StartsWith("\uFEFF", StringComparison.Ordinal))
                {
                    xmlPart = xmlPart.Substring(1);
                }

                System.Xml.XmlDocument xmlDoc = new System.Xml.XmlDocument();
                xmlDoc.LoadXml(xmlPart);

                StringBuilder formattedXml = new StringBuilder();
                using (System.IO.StringWriter stringWriter = new System.IO.StringWriter(formattedXml))
                {
                    using (System.Xml.XmlTextWriter writer = new System.Xml.XmlTextWriter(stringWriter))
                    {
                        writer.Formatting = System.Xml.Formatting.Indented;
                        writer.IndentChar = ' ';
                        writer.Indentation = 4;
                        xmlDoc.Save(writer);
                    }
                }

                string cleanXml = formattedXml.ToString();
                return beforeXml + cleanXml;
            }
            catch (Exception ex)
            {
                return output + $"\n\nОшибка форматирования XML: {ex.Message}";
            }
        }

        private async void RunVirusTotalCheck()
        {
            vtAttempts = 0;
            fullVtLinks.Clear();
            _vtLoadingDotsCount = 0;
            _vtLoadingTimer.Start();

            string initialText = GetTabText(5);

            await CheckVirusTotalWithRetry();

            ApplyAlarmSettings();
        }

        private async Task CheckVirusTotalWithRetry()
        {
            bool resultReceived = false;
            string lastOutput = "";

            while (vtAttempts < MAX_VT_ATTEMPTS && !resultReceived)
            {
                vtAttempts++;
                System.Diagnostics.Debug.WriteLine($"Попытка VirusTotal #{vtAttempts} из {MAX_VT_ATTEMPTS}");

                string vtParams = "-v";
                if (checkBoxRParam.IsChecked == true) vtParams += "r";
                if (checkBoxSParam.IsChecked == true) vtParams += "s";

                string output = await RunSigcheckAsync($"-nobanner {vtParams} \"{selectedFile}\"");
                System.Diagnostics.Debug.WriteLine($"Sigcheck Output (raw, попытка {vtAttempts}): {output}");

                if (output.Contains("VT detection:") && !output.Contains("Unknown"))
                {
                    string fullLink = ExtractVtLink(output);
                    System.Diagnostics.Debug.WriteLine($"Извлеченная полная VT ссылка (попытка {vtAttempts}): {fullLink}");

                    if (!string.IsNullOrEmpty(fullLink))
                    {
                        resultReceived = true;
                        _vtLoadingTimer.Stop();
                        fullVtLinks[5] = fullLink;
                    SetVirusTotalContent(output, fullLink);
                }
                    else
                    {
                        lastOutput = output;
                        SetVirusTotalContent(output, null); 
                        System.Diagnostics.Debug.WriteLine($"Ожидание результатов VirusTotal (попытка {vtAttempts})...");
                        await Task.Delay(2000);
                    }
                }
                else if (output.Contains("Submitted to VirusTotal"))
                {
                    lastOutput = output;
                    SetVirusTotalContent(output, null); 
                    System.Diagnostics.Debug.WriteLine($"Файл отправлен в VirusTotal, ожидание результатов (попытка {vtAttempts})...");
                    await Task.Delay(2000);
                }
                else if (output.Contains("VT detection: Unknown"))
                {
                    lastOutput = output;
                    resultReceived = true;
                    _vtLoadingTimer.Stop();
                    System.Diagnostics.Debug.WriteLine($"Обнаружение VirusTotal: Неизвестно (попытка {vtAttempts}). Завершение попыток.");
                    SetVirusTotalContent(lastOutput, null);
                }
                else
                {
                    lastOutput = output;
                    resultReceived = true;
                    _vtLoadingTimer.Stop();
                    System.Diagnostics.Debug.WriteLine($"Неожиданный вывод Sigcheck.exe (попытка {vtAttempts}). Завершение попыток.\nВывод: {output}");
                    SetVirusTotalContent(lastOutput, null);
                }
            }

            if (!resultReceived)
            {
                _vtLoadingTimer.Stop();
                System.Diagnostics.Debug.WriteLine($"Не удалось получить результаты VirusTotal после {MAX_VT_ATTEMPTS} попыток.");
                SetTabText(5, lastOutput + "\n\nНе удалось получить результаты VirusTotal в течение 60 секунд. Попробуйте еще раз позже.");
            }
        }

        private string ExtractVtLink(string output)
        {
            const string marker = "VT link:";
            int linkStart = output.IndexOf(marker);
            if (linkStart < 0) return null;

            linkStart += marker.Length;
            int linkEnd = output.IndexOf('\n', linkStart);
            if (linkEnd < 0) linkEnd = output.Length;

            string link = output.Substring(linkStart, linkEnd - linkStart).Trim();
            if (link.StartsWith("http://") || link.StartsWith("https://"))
            {
                return link;
            }
            return null;
        }

        private void SetVirusTotalContent(string output, string fullLink)
        {
            if (tabControlResults.Items.Count > 5 && tabControlResults.Items[5] is TabItem tabItem && tabItem.Content is RichTextBox rtb)
            {
                rtb.Document.Blocks.Clear();
                Paragraph paragraph = new Paragraph();

                int vtLinkIndex = output.IndexOf("https://www.virustotal.com/");
                string mainText = output;
                string linkText = null;
                if (vtLinkIndex > 0)
                {
                    mainText = output.Substring(0, vtLinkIndex).TrimEnd();
                    int linkEnd = output.IndexOfAny(new[] {'\n', '\r'}, vtLinkIndex);
                    if (linkEnd > vtLinkIndex)
                        linkText = output.Substring(vtLinkIndex, linkEnd - vtLinkIndex).Trim();
                    else
                        linkText = output.Substring(vtLinkIndex).Trim();
                }
                paragraph.Inlines.Add(new Run(mainText));
                paragraph.Inlines.Add(new LineBreak());
                if (!string.IsNullOrEmpty(linkText))
                {
                    paragraph.Inlines.Add(new Run(linkText));
                    paragraph.Inlines.Add(new LineBreak());
                }
                rtb.Document.Blocks.Add(paragraph);
            }
        }

        private void CalculateAndDisplayEntropy()
        {
            if (string.IsNullOrEmpty(selectedFile)) return;

            SetTabText(6, "Расчет энтропии...");

            try
            {
                byte[] fileBytes = File.ReadAllBytes(selectedFile);
                double totalEntropy = CalculateEntropy(fileBytes);

                StringBuilder sb = new StringBuilder();
                sb.AppendLine($"Общая энтропия файла: {totalEntropy:F6}");

                if (IsPEHeader(fileBytes))
                {
                    int peOffset = BitConverter.ToInt32(fileBytes, 0x3C);
                    int peHeaderSize = 24;
                    int optionalHeaderSize = BitConverter.ToUInt16(fileBytes, peOffset + 20);
                    int sectionTableOffset = peOffset + 24 + optionalHeaderSize;

                    double dosHeaderEntropy = CalculateEntropy(fileBytes.Take(peOffset).ToArray());
                    sb.AppendLine($"\nDOS Header энтропия: {dosHeaderEntropy:F6}");

                    double peHeaderEntropy = CalculateEntropy(fileBytes.Skip(peOffset).Take(peHeaderSize).ToArray());
                    sb.AppendLine($"PE Header энтропия: {peHeaderEntropy:F6}");

                    if (optionalHeaderSize > 0)
                    {
                        double optionalHeaderEntropy = CalculateEntropy(
                            fileBytes.Skip(peOffset + 24).Take(optionalHeaderSize).ToArray());
                        sb.AppendLine($"Optional Header энтропия: {optionalHeaderEntropy:F6}");
                    }

                    sb.AppendLine("\nЭнтропия секций:");
                    List<SectionHeader> sections = ParsePESections(selectedFile);
                    if (sections != null && sections.Count > 0)
                    {
                        foreach (var section in sections)
                        {
                            try
                            {
                                if (section.PointerToRawData + section.SizeOfRawData > fileBytes.Length)
                                    continue;

                                byte[] sectionData = new byte[section.SizeOfRawData];
                                Array.Copy(fileBytes, (int)section.PointerToRawData, sectionData, 0, (int)section.SizeOfRawData);
                                double sectionEntropy = CalculateEntropy(sectionData);
                                sb.AppendLine($"{section.Name}: {sectionEntropy:F6} (размер: {section.SizeOfRawData} байт)");
                            }
                            catch (Exception ex)
                            {
                                sb.AppendLine($"{section.Name}: Ошибка - {ex.Message}");
                            }
                        }
                    }
                    else
                    {
                        sb.AppendLine("Не удалось извлечь секции PE-файла");
                    }
                }
                else
                {
                    sb.AppendLine("\nФайл не является PE-исполняемым");
                }

                SetTabText(6, sb.ToString());
            }
            catch (Exception ex)
            {
                SetTabText(6, $"Ошибка расчета энтропии: {ex.Message}");
            }
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0.0;

            int[] freq = new int[256];
            foreach (byte b in data) freq[b]++;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] > 0)
                {
                    double p = (double)freq[i] / data.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return entropy;
        }

        private bool IsPEHeader(byte[] data)
        {
            if (data.Length < 64) return false;

            if (data[0] != 'M' || data[1] != 'Z')
                return false;

            if (data.Length < 0x3C + 4)
                return false;

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset + 24 > data.Length)
                return false;

            return data[peOffset] == 'P' &&
                   data[peOffset + 1] == 'E' &&
                   data[peOffset + 2] == 0 &&
                   data[peOffset + 3] == 0;
        }

        private List<SectionHeader> ParsePESections(string filePath)
        {
            try
            {
                byte[] data = File.ReadAllBytes(filePath);

                if (data[0] != 'M' || data[1] != 'Z')
                    return null;

                int peOffset = BitConverter.ToInt32(data, 0x3C);
                if (peOffset + 24 > data.Length)
                    return null;

                if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
                    return null;

                int numberOfSections = BitConverter.ToUInt16(data, peOffset + 6);
                int sizeOfOptionalHeader = BitConverter.ToUInt16(data, peOffset + 20);

                int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
                if (sectionTableOffset + 40 * numberOfSections > data.Length)
                    return null;

                List<SectionHeader> sections = new List<SectionHeader>();
                for (int i = 0; i < numberOfSections; i++)
                {
                    int offset = sectionTableOffset + i * 40;
                    SectionHeader section = new SectionHeader
                    {
                        Name = Encoding.ASCII.GetString(data, offset, 8).TrimEnd('\0'),
                        VirtualSize = BitConverter.ToUInt32(data, offset + 8),
                        VirtualAddress = BitConverter.ToUInt32(data, offset + 12),
                        SizeOfRawData = BitConverter.ToUInt32(data, offset + 16),
                        PointerToRawData = BitConverter.ToUInt32(data, offset + 20),
                        Characteristics = BitConverter.ToUInt32(data, offset + 36)
                    };
                    sections.Add(section);
                }

                return sections;
            }
            catch
            {
                return null;
            }
        }

        private string GetTabText(int tabIndex)
        {
            if (tabIndex >= 0 && tabIndex < tabControlResults.Items.Count)
            {
                if (tabControlResults.Items[tabIndex] is TabItem tabItem && tabItem.Content is RichTextBox rtb)
                {
                    TextRange textRange = new TextRange(rtb.Document.ContentStart, rtb.Document.ContentEnd);
                    return textRange.Text;
                }
            }
            return string.Empty;
        }

        private void SetTabText(int tabIndex, string text)
        {
            if (tabIndex >= 0 && tabIndex < tabControlResults.Items.Count)
            {
                TabItem tabItem = tabControlResults.Items[tabIndex] as TabItem;
                if (tabItem != null && tabItem.Content is RichTextBox rtb)
                {
                    rtb.Document.Blocks.Clear();
                    rtb.Document.Blocks.Add(new Paragraph(new Run(text)));
                }
            }
        }

        private void ButtonRefresh_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(selectedFile))
            {
                RunSigcheckAll();
            }
            else
            {
                MessageBox.Show("Нет выбранного файла для обновления.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ButtonSaveReport_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog();
            sfd.Filter = "Текстовые файлы (*.txt)|*.txt";
            sfd.FileName = "sigcheck_report.txt";
            if (sfd.ShowDialog() == true)
            {
                StringBuilder sb = new StringBuilder();
                foreach (TabItem tab in tabControlResults.Items)
                {
                    if (tab.Content is RichTextBox rtb)
                    {
                        sb.AppendLine($"=== {tab.Header} ===");
                        TextRange textRange = new TextRange(rtb.Document.ContentStart, rtb.Document.ContentEnd);
                        if (tab.Header.ToString().Contains("VirusTotal") && fullVtLinks.TryGetValue(5, out string fullLink))
                        {
                            string report = textRange.Text;
                            if (report.Contains("VT link:"))
                            {
                                int linkStart = report.IndexOf("VT link:") + "VT link:".Length;
                                int linkEnd = report.IndexOf('\n', linkStart);
                                if (linkEnd < 0) linkEnd = report.Length;

                                string beforeLink = report.Substring(0, linkStart);
                                string afterLink = report.Substring(linkEnd);
                                report = beforeLink + " " + fullLink + afterLink;
                            }
                            sb.AppendLine(report);
                        }
                        else
                        {
                            sb.AppendLine(textRange.Text);
                        }
                        sb.AppendLine();
                    }
                }
                File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);

                MessageBoxResult result = MessageBox.Show("Отчёт сохранён.\nХотите открыть папку с отчетом?",
                    "Готово", MessageBoxButton.YesNo, MessageBoxImage.Information);

                if (result == MessageBoxResult.Yes)
                {
                    Process.Start("explorer.exe", $"/select, \"{sfd.FileName}\"");
                }
            }
        }

        private void ButtonSaveReportRu_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog();
            sfd.Filter = "Текстовые файлы (*.txt)|*.txt";
            sfd.FileName = "sigcheck_report_ru.txt";
            if (sfd.ShowDialog() == true)
            {
                StringBuilder sb = new StringBuilder();
                foreach (TabItem tab in tabControlResults.Items)
                {
                    if (tab.Content is RichTextBox rtb)
                    {
                        sb.AppendLine($"=== {tab.Header} ===");
                        TextRange textRange = new TextRange(rtb.Document.ContentStart, rtb.Document.ContentEnd);
                        if (tab.Header.ToString().Contains("VirusTotal") && fullVtLinks.TryGetValue(5, out string fullLink))
                        {
                            string report = textRange.Text;
                            if (report.Contains("VT link:"))
                            {
                                int linkStart = report.IndexOf("VT link:") + "VT link:".Length;
                                int linkEnd = report.IndexOf('\n', linkStart);
                                if (linkEnd < 0) linkEnd = report.Length;

                                string beforeLink = report.Substring(0, linkStart);
                                string afterLink = report.Substring(linkEnd);
                                report = beforeLink + " " + fullLink + afterLink;
                            }
                            sb.AppendLine(TranslateSigcheckReport(report));
                        }
                        else
                        {
                            sb.AppendLine(TranslateSigcheckReport(textRange.Text));
                        }
                        sb.AppendLine();
                    }
                }
                File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);

                MessageBoxResult result = MessageBox.Show("Отчёт сохранён.\nХотите открыть папку с отчетом?",
                    "Готово", MessageBoxButton.YesNo, MessageBoxImage.Information);

                if (result == MessageBoxResult.Yes)
                {
                    Process.Start("explorer.exe", $"/select, \"{sfd.FileName}\"");
                }
            }
        }

        private string TranslateSigcheckReport(string report)
        {
            foreach (var kv in sigcheckRuDict)
                report = report.Replace(kv.Key, kv.Value);
            return report;
        }

        private void ButtonSettings_Click(object sender, RoutedEventArgs e)
        {
            settingsWindow.ShowSettings();
        }

        private void ButtonFile_Click(object sender, RoutedEventArgs e)
        {
            ButtonSelectFile_Click(sender, e);
        }

        public void ApplyAlarmSettings()
        {
            System.Diagnostics.Debug.WriteLine("ApplyAlarmSettings вызван! Количество настроек: " + AlarmSettings.Count);
            Debug.WriteLine("\nНачало применения настроек тревог.");
            Debug.WriteLine($"Количество настроек тревог: {AlarmSettings.Count}");

            foreach (TabItem tab in tabControlResults.Items)
            {
                tab.Tag = false;
                tab.Background = SystemColors.ControlBrush;

                if (tab.Content is RichTextBox rtb)
                {
                    Debug.WriteLine($"Проверка вкладки: {tab.Header}");
                    TextRange textRange = new TextRange(rtb.Document.ContentStart, rtb.Document.ContentEnd);
                    string[] lines = textRange.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.None);
                    bool tabHasAlarm = false;

                    for (int i = 0; i < lines.Length; i++)
                    {
                         if (lines[i].Contains(" (!ALARM!)"))
                         {
                             lines[i] = lines[i].Replace(" (!ALARM!)", "").TrimEnd();
                         }
                    }

                    FlowDocument newDocument = new FlowDocument();
                    Paragraph paragraph = new Paragraph();

                    for (int i = 0; i < lines.Length; i++)
                    {
                        bool lineHasAlarm = false;
                        string newLine = lines[i];

                        Debug.WriteLine($"Обработка строки {i + 1}: {newLine}");

                        foreach (var setting in AlarmSettings)
                        {
                            if (!setting.Enabled) continue;

                            string extractedValue = null;
                            string parameterToMatch = setting.Parameter;

                            if (parameterToMatch == "Signing date")
                            {
                                if (newLine.Contains("Signing date:"))
                                {
                                    extractedValue = newLine.Split(new[] { "Signing date:" }, StringSplitOptions.None)[1].Trim();
                                }
                                else if (newLine.Contains("Link date:"))
                                {
                                    extractedValue = newLine.Split(new[] { "Link date:" }, StringSplitOptions.None)[1].Trim();
                                }
                            }
                            else if (parameterToMatch == "assemblyIdentity")
                            {
                                if (newLine.Contains("assemblyIdentity"))
                                {
                                    extractedValue = newLine;
                                }
                            }
                            else if (parameterToMatch == "Общая энтропия файла" && tab.Header.ToString().Contains("All Info (-a)") && newLine.TrimStart().StartsWith("Entropy:"))
                            {
                                var match = System.Text.RegularExpressions.Regex.Match(newLine, @"Entropy:\s*([-+]?[0-9]*[\.,]?[0-9]+)");
                                if (match.Success)
                                {
                                    extractedValue = match.Groups[1].Value.Replace(",", ".");
                                }
                            }
                            else if (parameterToMatch == "Энтропия секций" && tab.Header.ToString().Contains("Энтропия"))
                            {
                                if (newLine.Contains(":") && !newLine.Contains("Общая энтропия"))
                                {
                                    int colonIndex = newLine.IndexOf(":");
                                    if (colonIndex >= 0)
                                    {
                                        string afterColon = newLine.Substring(colonIndex + 1);
                                        var match = System.Text.RegularExpressions.Regex.Match(afterColon, @"([-+]?[0-9]*[.,]?[0-9]+)");
                                        if (match.Success)
                                        {
                                            extractedValue = match.Value.Replace(",", ".");
                                        }
                                    }
                                }
                            }
                            else if (parameterToMatch == "Description" || parameterToMatch == "Original Name" || parameterToMatch == "Internal Name" || parameterToMatch == "Publisher")
                            {
                                if (newLine.Contains(parameterToMatch + ":"))
                                {
                                    extractedValue = newLine.Split(new[] { parameterToMatch + ":" }, StringSplitOptions.None)[1].Trim();
                                }
                            }
                            else if (newLine.Contains(parameterToMatch + ":"))
                            {
                                extractedValue = newLine.Split(new[] { parameterToMatch + ":" }, StringSplitOptions.None)[1].Trim();
                            }

                            if (extractedValue != null)
                            {
                                Debug.WriteLine($"Параметр: {setting.Parameter}, Извлеченное значение: '{extractedValue}', Условие: {setting.Condition}, Порог: {setting.Value}");
                                if (setting.CheckAlarm(extractedValue) || extractedValue.Trim().Trim(':').Trim() == "???" || System.Text.RegularExpressions.Regex.IsMatch(extractedValue.Trim(), @"\?")){
                                    lineHasAlarm = true;
                                    Debug.WriteLine($"Тревога сработала для строки: {newLine}");
                                    Debug.WriteLine($"Значение lineHasAlarm после CheckAlarm: {lineHasAlarm}");
                                    break; 
                                }
                                else
                                {
                                    Debug.WriteLine($"Тревога НЕ сработала для строки: {newLine}");
                                    Debug.WriteLine($"Значение lineHasAlarm после CheckAlarm: {lineHasAlarm}");
                                }
                            }
                        }

                        if (lineHasAlarm && !newLine.Contains("(!ALARM!)"))
                        {
                            Debug.WriteLine($"Добавляем метку тревоги к строке: '{newLine}'");
                            newLine += " (!ALARM!)";
                            tabHasAlarm = true;
                            Debug.WriteLine($"Строка после добавления метки: '{newLine}'");
                        }

                        Run run = new Run(newLine + Environment.NewLine);
                        if (lineHasAlarm)
                        {
                            run.Background = Brushes.LightCoral; 
                            Debug.WriteLine($"Фон строки установлен в LightCoral для: '{newLine}'");
                        }
                        paragraph.Inlines.Add(run);
                    }

                    newDocument.Blocks.Add(paragraph);
                    rtb.Document = newDocument;

                    if (tabHasAlarm)
                    {
                        tab.Tag = true;
                        Debug.WriteLine($"Вкладка '{tab.Header}' помечена как содержащая тревогу. tab.Tag = {tab.Tag}");
                    }
                    else
                    {
                        tab.Tag = false;
                        Debug.WriteLine($"Вкладка '{tab.Header}' не содержит тревог. tab.Tag = {tab.Tag}");
                    }
                }
            }
            Debug.WriteLine("Завершение применения настроек тревог.");
        }

        private struct SectionHeader
        {
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint Characteristics;
        }

        private void LoadAlarmSettings()
        {
            System.Diagnostics.Debug.WriteLine("LoadAlarmSettings: Загрузка глобальных настроек тревог из AppSettings...");
            System.Diagnostics.Debug.WriteLine($"LoadAlarmSettings: В AppSettings.Instance.GlobalAlarmSettings содержится {AppSettings.Instance.GlobalAlarmSettings.Count} настроек");
            
            if (!AppSettings.Instance.GlobalAlarmSettings.Any())
            {
                System.Diagnostics.Debug.WriteLine("LoadAlarmSettings: Глобальные настройки тревог пусты, загружаем дефолтные.");
                AppSettings.Instance.GlobalAlarmSettings = GetDefaultAlarmSettings();
                AppSettings.Instance.SaveSettings();
                System.Diagnostics.Debug.WriteLine($"LoadAlarmSettings: Загружено {AppSettings.Instance.GlobalAlarmSettings.Count} дефолтных настроек");
            }

            AlarmSettings.Clear();
            foreach (var setting in AppSettings.Instance.GlobalAlarmSettings)
            {
                AlarmSettings.Add(setting);
            }
            System.Diagnostics.Debug.WriteLine($"LoadAlarmSettings: Загружено {AlarmSettings.Count} глобальных настроек тревог.");
            

            foreach (var alarm in AlarmSettings)
            {
                System.Diagnostics.Debug.WriteLine($"LoadAlarmSettings: Загружен аларм: {alarm.Parameter} = {alarm.Value} (Enabled: {alarm.Enabled})");
            }
        }

        public void UpdateGlobalAlarmSettingsFromCurrent()
        {
            System.Diagnostics.Debug.WriteLine("UpdateGlobalAlarmSettingsFromCurrent: Сохранение текущих настроек тревог в глобальные настройки AppSettings...");
            System.Diagnostics.Debug.WriteLine($"UpdateGlobalAlarmSettingsFromCurrent: Текущих алармов в MainWindow: {AlarmSettings.Count}");
            
            if (AppSettings.Instance.EnableIndividualHistorySettings)
            {
                System.Diagnostics.Debug.WriteLine("UpdateGlobalAlarmSettingsFromCurrent: Отклонено сохранение глобальных настроек, так как включены индивидуальные настройки.");
                return;
            }

            AppSettings.Instance.GlobalAlarmSettings = new List<AlarmSetting>(AlarmSettings);
            AppSettings.Instance.SaveSettings();
            
            System.Diagnostics.Debug.WriteLine($"UpdateGlobalAlarmSettingsFromCurrent: Сохранено {AlarmSettings.Count} глобальных настроек тревог.");
            System.Diagnostics.Debug.WriteLine($"UpdateGlobalAlarmSettingsFromCurrent: В AppSettings теперь {AppSettings.Instance.GlobalAlarmSettings.Count} алармов");
        }

        public void UpdateGlobalYaraRulesFromCurrent()
        {
            System.Diagnostics.Debug.WriteLine("SaveYaraRulesAndApply: Сохранение текущих правил YARA в глобальные настройки AppSettings и применение...");
            if (AppSettings.Instance.EnableIndividualHistorySettings)
            {
                System.Diagnostics.Debug.WriteLine("UpdateGlobalYaraRulesFromCurrent: Отклонено сохранение глобальных правил YARA, так как включены индивидуальные настройки.");
                return;
            }
            AppSettings.Instance.GlobalYaraRules = new List<YaraRule>(_yaraRules);
            AppSettings.Instance.SaveSettings();

            System.Diagnostics.Debug.WriteLine($"SaveYaraRulesAndApply: Сохранено {YaraRules.Count} глобальных правил YARA.");
        }

        private List<AlarmSetting> GetDefaultAlarmSettings()
        {
            return new List<AlarmSetting>
            {
                new AlarmSetting { Enabled = true, Parameter = "Verified", Condition = "Не 'Signed'", Value = "", Tab = "All Info (-a)", Description = "Проверка наличия цифровой подписи файла" },
                new AlarmSetting { Enabled = true, Parameter = "Signing date", Condition = "Дата <", Value = "1980-01-01", Tab = "All Info (-a)", Description = "Проверка даты подписания файла" },
                new AlarmSetting { Enabled = true, Parameter = "VT detection", Condition = ">", Value = "0", Tab = "VirusTotal (-v)", Description = "Проверка количества обнаружений в VirusTotal" },
                new AlarmSetting { Enabled = true, Parameter = "Энтропия секций", Condition = ">", Value = "5.5", Tab = "Энтропия", Description = "Проверка энтропии отдельных секций" },
                new AlarmSetting { Enabled = true, Parameter = "Общая энтропия файла", Condition = ">", Value = "5.5", Tab = "Энтропия", Description = "Проверка общей энтропии файла" },
                new AlarmSetting { Enabled = true, Parameter = "File version", Condition = "Версия <", Value = "X.X.X.X", Tab = "All Info (-a)", Description = "Проверка версии файла" },
                new AlarmSetting { Enabled = true, Parameter = "Prod version", Condition = "Версия <", Value = "X.X.X.X", Tab = "All Info (-a)", Description = "Проверка версии продукта" },
                new AlarmSetting { Enabled = true, Parameter = "Binary Version", Condition = "Версия <", Value = "X.X.X.X", Tab = "All Info (-a)", Description = "Проверка бинарной версии" },
                new AlarmSetting { Enabled = true, Parameter = "assemblyIdentity", Condition = "Содержит", Value = "MyApplication.app", Tab = "Manifest (-m)", Description = "Проверка идентификатора сборки" },
                new AlarmSetting { Enabled = true, Parameter = "Publisher", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка издателя" },
                new AlarmSetting { Enabled = true, Parameter = "Comments", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка комментариев файла" },
                new AlarmSetting { Enabled = true, Parameter = "Company", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка названия компании" },
                new AlarmSetting { Enabled = true, Parameter = "Description", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка описания файла" },
                new AlarmSetting { Enabled = true, Parameter = "Original Name", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка оригинального имени файла" },
                new AlarmSetting { Enabled = true, Parameter = "Internal Name", Condition = "Содержит", Value = "n/a", Tab = "All Info (-a)", Description = "Проверка внутреннего имени файла" }
            };
        }

        private void rtbVirusTotal_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            RichTextBox rtb = sender as RichTextBox;
            if (rtb == null) return;

            DependencyObject dep = (DependencyObject)e.OriginalSource;
            while ((dep != null) && !(dep is Run) && !(dep is Hyperlink))
            {
                dep = VisualTreeHelper.GetParent(dep);
            }

            if (dep is Hyperlink link)
            {
                if (link.NavigateUri != null)
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(link.NavigateUri.AbsoluteUri) { UseShellExecute = true });
                    e.Handled = true;
                }
            }
        }

        private async void tabControlResults_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (tabControlResults.SelectedItem is TabItem selectedTab)
            {
                string header = selectedTab.Header.ToString();
                if (header == "YARA")
                {
                    SetTabText(7, "Загрузка YARA-правил...");
                    var report = await Task.Run(() => GenerateYaraRulesReport());
                    SetTabText(7, report);
                }
                else if (header == "История")
                {
                    LoadFileHistory();
                }
            }
        }


        public async void RunYaraScan()
        {
            if (string.IsNullOrEmpty(selectedFile))
            {
                SetTabText(7, "");
                SetTabText(9, "");
                SetTabText(10, "");
                return;
            }

            string yaraExePath = GetYaraPath();
            if (string.IsNullOrEmpty(yaraExePath) || !File.Exists(yaraExePath))
            {
                SetTabText(7, $"Не найден yara64.exe по пути: {yaraExePath}\nПоложите yara64.exe рядом с SigcheckGUI.exe");
                return;
            }

            var enabledRules = YaraRules.Where(r => r.Enabled && File.Exists(r.RulePath)).ToList();
            if (enabledRules.Count == 0)
            {
                SetTabText(7, "Нет активных YARA-правил.");
                return;
            }

            StringBuilder result = new StringBuilder();
            result.AppendLine($"YARA-сканирование файла: {Path.GetFileName(selectedFile)}");
            result.AppendLine($"Время сканирования: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            result.AppendLine($"Количество активных правил: {enabledRules.Count}");
            result.AppendLine(new string('-', 50));
            result.AppendLine();

            string combinedRulesPath = LoadCombinedYaraRulesPath();
            if (!string.IsNullOrEmpty(combinedRulesPath) && File.Exists(combinedRulesPath))
            {
                try
                {
                    result.AppendLine("=== Сканирование с объединенным файлом правил ===");
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = yaraExePath,
                        Arguments = $"\"{combinedRulesPath}\" \"{selectedFile}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                    };
                    
                    using (Process proc = Process.Start(psi))
                    {
                        string output = proc.StandardOutput.ReadToEnd();
                        string error = proc.StandardError.ReadToEnd();
                        proc.WaitForExit();
                        
                        if (!string.IsNullOrWhiteSpace(output))
                        {
                            result.AppendLine(output);
                        }
                        if (!string.IsNullOrWhiteSpace(error))
                        {
                            result.AppendLine($"Ошибки: {error}");
                        }
                        
                        if (string.IsNullOrWhiteSpace(output) && string.IsNullOrWhiteSpace(error))
                        {
                            result.AppendLine("Совпадений не найдено.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.AppendLine($"Ошибка при сканировании с объединенным файлом: {ex.Message}");
                    result.AppendLine("Переключаемся на индивидуальное сканирование правил...");
                    result.AppendLine();
                    
                    await ScanIndividualRules(enabledRules, result);
                }
            }
            else
            {
                await ScanIndividualRules(enabledRules, result);
            }

            result.AppendLine();
            result.AppendLine(new string('-', 50));
            result.AppendLine($"Сканирование завершено: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            
            SetTabText(7, result.ToString());
            YaraSettings.Instance.Rules = YaraRules;
        }

        private async Task ScanIndividualRules(List<YaraRule> enabledRules, StringBuilder result)
        {
            result.AppendLine("=== Сканирование с индивидуальными правилами ===");
            
            string yaraExePath = GetYaraPath();
            if (string.IsNullOrEmpty(yaraExePath) || !File.Exists(yaraExePath))
            {
                result.AppendLine($"ОШИБКА: Не найден yara64.exe по пути: {yaraExePath}");
                return;
            }
            
            foreach (var rule in enabledRules)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = yaraExePath,
                        Arguments = $"\"{rule.RulePath}\" \"{selectedFile}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                    };
                    
                    using (Process proc = Process.Start(psi))
                    {
                        string output = proc.StandardOutput.ReadToEnd();
                        string error = proc.StandardError.ReadToEnd();
                        proc.WaitForExit();
                        
                        result.AppendLine($"--- {rule.Description} ---");
                        if (!string.IsNullOrWhiteSpace(output))
                        {
                            result.AppendLine(output);
                        }
                        if (!string.IsNullOrWhiteSpace(error))
                        {
                            result.AppendLine($"Ошибка: {error}");
                        }
                        if (string.IsNullOrWhiteSpace(output) && string.IsNullOrWhiteSpace(error))
                        {
                            result.AppendLine("Совпадений не найдено.");
                        }
                        result.AppendLine();
                    }
                }
                catch (Exception ex)
                {
                    result.AppendLine($"Ошибка запуска YARA для {rule.RulePath}: {ex.Message}");
                    result.AppendLine();
                }
            }
        }

        public void SaveYaraPath(string path)
        {
            try
            {
                var rule = new YaraRule { Enabled = true, RulePath = path, Description = "YARA" };
                YaraSettings.Instance.Rules = _yaraRules;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при сохранении пути YARA: {ex.Message}");
            }
        }

        public string LoadYaraPath()
        {
            try
            {
                var rules = YaraSettings.Instance.Rules;
                if (rules.Any())
                {
                    var lastRule = rules.Last();
                    if (File.Exists(lastRule.RulePath))
                        return lastRule.RulePath;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при загрузке пути YARA: {ex.Message}");
            }
            return null;
        }

        private void SelectYaraFile_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new Microsoft.Win32.OpenFileDialog();
            ofd.Filter = "YARA-файлы (*.yar;*.yara;*.txt)|*.yar;*.yara;*.txt|Все файлы (*.*)|*.*";
            if (ofd.ShowDialog() == true)
            {
                _yaraRules.Clear();
                var rule = new YaraRule { Enabled = true, RulePath = ofd.FileName, Description = "YARA" };
                _yaraRules.Add(rule);
                SaveYaraRulesAndApply();
            }
        }

        private string CreateCombinedYaraRulesFile()
        {
            try
            {
                var enabledRules = YaraRules.Where(r => r.Enabled && File.Exists(r.RulePath)).ToList();
                if (enabledRules.Count == 0)
                {
                    return null;
                }

                string combinedRulesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "combined_yara_rules.yar");
                StringBuilder combinedContent = new StringBuilder();
                
                combinedContent.AppendLine("// Объединенные YARA правила");
                combinedContent.AppendLine($"// Создано: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                combinedContent.AppendLine($"// Количество правил: {enabledRules.Count}");
                combinedContent.AppendLine();

                foreach (var rule in enabledRules)
                {
                    try
                    {
                        string ruleContent = File.ReadAllText(rule.RulePath);
                        combinedContent.AppendLine($"// === {rule.Description} ===");
                        combinedContent.AppendLine($"// Источник: {rule.RulePath}");
                        combinedContent.AppendLine(ruleContent);
                        combinedContent.AppendLine();
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Ошибка при чтении правила {rule.RulePath}: {ex.Message}");
                        combinedContent.AppendLine($"// ОШИБКА: Не удалось прочитать правило {rule.RulePath}");
                        combinedContent.AppendLine($"// {ex.Message}");
                        combinedContent.AppendLine();
                    }
                }

                File.WriteAllText(combinedRulesPath, combinedContent.ToString());
                System.Diagnostics.Debug.WriteLine($"Создан объединенный файл YARA правил: {combinedRulesPath}");
                return combinedRulesPath;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при создании объединенного файла YARA правил: {ex.Message}");
                return null;
            }
        }

        private void ApplyYaraRulesOnStartup()
        {
            try
            {
                if (YaraRules.Any(r => r.Enabled && File.Exists(r.RulePath)))
                {
                    System.Diagnostics.Debug.WriteLine("ApplyYaraRulesOnStartup: Применяем YARA правила при запуске...");
                    
                    string combinedRulesPath = CreateCombinedYaraRulesFile();
                    if (!string.IsNullOrEmpty(combinedRulesPath))
                    {
                        SaveCombinedYaraRulesPath(combinedRulesPath);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при применении YARA правил при запуске: {ex.Message}");
            }
        }

        private void SaveCombinedYaraRulesPath(string combinedRulesPath)
        {
            try
            {
                string pathFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "combined_yara_path.txt");
                File.WriteAllText(pathFile, combinedRulesPath);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при сохранении пути к объединенному файлу YARA: {ex.Message}");
            }
        }

        private string LoadCombinedYaraRulesPath()
        {
            try
            {
                string pathFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "combined_yara_path.txt");
                if (File.Exists(pathFile))
                {
                    string path = File.ReadAllText(pathFile).Trim();
                    if (File.Exists(path))
                    {
                        return path;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при загрузке пути к объединенному файлу YARA: {ex.Message}");
            }
            return null;
        }

        public void UpdateCombinedYaraRules()
        {
            try
            {
                string combinedRulesPath = CreateCombinedYaraRulesFile();
                if (!string.IsNullOrEmpty(combinedRulesPath))
                {
                    SaveCombinedYaraRulesPath(combinedRulesPath);
                    System.Diagnostics.Debug.WriteLine("UpdateCombinedYaraRules: Объединенный файл YARA правил обновлен");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при обновлении объединенного файла YARA правил: {ex.Message}");
            }
        }

        public string ValidateYaraRulesSyntax()
        {
            if (string.IsNullOrEmpty(selectedFile)) return "";

            string validationResult = "";
            string combinedRulesPath = CreateCombinedYaraRulesFile();

            if (string.IsNullOrEmpty(combinedRulesPath) || !File.Exists(combinedRulesPath))
            {
                validationResult = "Combined YARA rules file not created or found.";
                return validationResult;
            }

            string yaraExePath = GetYaraPath();
            if (string.IsNullOrEmpty(yaraExePath) || !File.Exists(yaraExePath))
            {
                validationResult = $"ОШИБКА: Не найден yara64.exe по пути: {yaraExePath}";
                return validationResult;
            }

            try
            {
            int validRules = 0;
            int invalidRules = 0;

                        string tempTestFile = Path.Combine(Path.GetTempPath(), "yara_empty_test.bin");
                        File.WriteAllBytes(tempTestFile, new byte[0]);

                        ProcessStartInfo psi = new ProcessStartInfo
                        {
                            FileName = yaraExePath,
                    Arguments = $"\"{combinedRulesPath}\" \"{tempTestFile}\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                        };

                        using (Process proc = Process.Start(psi))
                        {
                            string output = proc.StandardOutput.ReadToEnd();
                            string error = proc.StandardError.ReadToEnd();
                            proc.WaitForExit();

                            try { File.Delete(tempTestFile); } catch { }

                            bool hasSyntaxError = false;
                            if (!string.IsNullOrWhiteSpace(error))
                            {
                                string errorLower = error.ToLower();
                                hasSyntaxError = errorLower.Contains("syntax error") || 
                                               errorLower.Contains("error") ||
                                               errorLower.Contains("invalid") ||
                                               errorLower.Contains("unexpected");
                            }

                            if (!hasSyntaxError)
                            {
                        validationResult = "✅ Синтаксис всех правил корректен!";
                                validRules++;
                            }
                            else
                            {
                        validationResult = "❌ ОШИБКА СИНТАКСИСА:";
                                if (!string.IsNullOrWhiteSpace(error))
                                {
                            validationResult += "\n" + error.Trim();
                                }
                                invalidRules++;
                            }
                        }

                validationResult += "\n\n=== ИТОГИ ПРОВЕРКИ СИНТАКСИСА ===";
                validationResult += "\nВсего правил: " + YaraRules.Count;
                validationResult += "\nКорректных: " + validRules;
                validationResult += "\nС ошибками: " + invalidRules;
                validationResult += "\n\n";

            if (invalidRules == 0)
            {
                    validationResult += "✅ Синтаксис всех правил корректен!";
            }
            else
            {
                    validationResult += "⚠️ Обнаружены синтаксические ошибки в правилах.";
            }

                return validationResult;
            }
            catch (Exception ex)
            {
                return $"Ошибка при проверке YARA правил: {ex.Message}";
            }
        }

        public string ValidateYaraRules()
        {
            if (string.IsNullOrEmpty(selectedFile)) return "";

            string validationResult = "";
            string combinedRulesPath = CreateCombinedYaraRulesFile();

            if (string.IsNullOrEmpty(combinedRulesPath) || !File.Exists(combinedRulesPath))
            {
                validationResult = "Combined YARA rules file not created or found.";
                return validationResult;
            }

            string yaraExePath = GetYaraPath();
            if (string.IsNullOrEmpty(yaraExePath) || !File.Exists(yaraExePath))
            {
                validationResult = $"ОШИБКА: Не найден yara64.exe по пути: {yaraExePath}";
                return validationResult;
            }

            try
            {
            int validRules = 0;
            int invalidRules = 0;

                        string tempTestFile = Path.Combine(Path.GetTempPath(), "yara_test_file.bin");
                        byte[] testData = new byte[1024];
                        System.Text.Encoding.ASCII.GetBytes("cmd.exe").CopyTo(testData, 0);
                        System.Text.Encoding.ASCII.GetBytes("powershell").CopyTo(testData, 100);
                        System.Text.Encoding.ASCII.GetBytes("UPX").CopyTo(testData, 200);
                        File.WriteAllBytes(tempTestFile, testData);

                        ProcessStartInfo psi = new ProcessStartInfo
                        {
                            FileName = yaraExePath,
                    Arguments = $"\"{combinedRulesPath}\" \"{tempTestFile}\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                        };

                        using (Process proc = Process.Start(psi))
                        {
                            string output = proc.StandardOutput.ReadToEnd();
                            string error = proc.StandardError.ReadToEnd();
                            proc.WaitForExit();

                            try { File.Delete(tempTestFile); } catch { }

                            bool hasSyntaxError = false;
                            if (!string.IsNullOrWhiteSpace(error))
                            {
                                string errorLower = error.ToLower();
                                hasSyntaxError = errorLower.Contains("syntax error") || 
                                               errorLower.Contains("error") ||
                                               errorLower.Contains("invalid") ||
                                               errorLower.Contains("unexpected");
                            }

                            if (!hasSyntaxError)
                            {
                        validationResult = "✅ Правило корректно";
                                if (!string.IsNullOrWhiteSpace(output))
                                {
                            validationResult += "\nРезультат тестирования: " + output.Trim();
                                }
                                else
                                {
                            validationResult += "\nРезультат тестирования: совпадений не найдено";
                                }
                                validRules++;
                            }
                            else
                            {
                        validationResult = "❌ ОШИБКА СИНТАКСИСА:";
                                if (!string.IsNullOrWhiteSpace(error))
                                {
                            validationResult += "\n" + error.Trim();
                                }
                                invalidRules++;
                            }
                        }

                validationResult += "\n\n=== ИТОГИ ПОЛНОЙ ПРОВЕРКИ ===";
                validationResult += "\nВсего правил: " + YaraRules.Count;
                validationResult += "\nКорректных: " + validRules;
                validationResult += "\nС ошибками: " + invalidRules;
                validationResult += "\n\n";

            if (invalidRules == 0)
            {
                    validationResult += "✅ Все правила корректны и готовы к использованию!";
            }
            else
            {
                    validationResult += "⚠️ Обнаружены ошибки в правилах. Исправьте их перед использованием.";
            }

                return validationResult;
            }
            catch (Exception ex)
            {
                return $"Ошибка при тестировании YARA правил: {ex.Message}";
            }
        }

        public string GenerateYaraRulesReport()
        {
            if (string.IsNullOrEmpty(selectedFile))
            {
                return string.Empty;
            }
            StringBuilder report = new StringBuilder();
            report.AppendLine("=== ОТЧЕТ ПО YARA ПРАВИЛАМ ===");
            report.AppendLine($"Время создания: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine();

            var allRules = YaraRules.ToList();
            if (allRules.Count == 0)
            {
                report.AppendLine("YARA правила не настроены.");
                return report.ToString();
            }

            var enabledRules = allRules.Where(r => r.Enabled).ToList();
            var disabledRules = allRules.Where(r => !r.Enabled).ToList();

            report.AppendLine($"Всего правил: {allRules.Count}");
            report.AppendLine($"Активных: {enabledRules.Count}");
            report.AppendLine($"Отключенных: {disabledRules.Count}");
            report.AppendLine();

            if (enabledRules.Count > 0)
            {
                report.AppendLine("=== АКТИВНЫЕ ПРАВИЛА ===");
                foreach (var rule in enabledRules)
                {
                    report.AppendLine($"• {rule.Description}");
                    report.AppendLine($"  Путь: {rule.RulePath}");
                    report.AppendLine($"  Статус: {(File.Exists(rule.RulePath) ? "✅ Файл найден" : "❌ Файл не найден")}");
                    report.AppendLine();
                }
            }

            if (disabledRules.Count > 0)
            {
                report.AppendLine("=== ОТКЛЮЧЕННЫЕ ПРАВИЛА ===");
                foreach (var rule in disabledRules)
                {
                    report.AppendLine($"• {rule.Description}");
                    report.AppendLine($"  Путь: {rule.RulePath}");
                    report.AppendLine();
                }
            }

            string combinedRulesPath = LoadCombinedYaraRulesPath();
            if (!string.IsNullOrEmpty(combinedRulesPath) && File.Exists(combinedRulesPath))
            {
                report.AppendLine("=== ОБЪЕДИНЕННЫЙ ФАЙЛ ПРАВИЛ ===");
                report.AppendLine($"Путь: {combinedRulesPath}");
                var fileInfo = new FileInfo(combinedRulesPath);
                report.AppendLine($"Размер: {fileInfo.Length} байт");
                report.AppendLine($"Создан: {fileInfo.CreationTime:yyyy-MM-dd HH:mm:ss}");
                report.AppendLine($"Изменен: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
            }

            return report.ToString();
        }

        private void ButtonValidateYara_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string validationResult = ValidateYaraRulesSyntax();
                SetTabText(8, validationResult);
                
                if (tabControlResults.Items.Count > 8)
                {
                    tabControlResults.SelectedIndex = 8;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при проверке YARA правил: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ButtonYaraReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string report = GenerateYaraRulesReport();
                SetTabText(9, report);
                
                if (tabControlResults.Items.Count > 9)
                {
                    tabControlResults.SelectedIndex = 9;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при создании отчета YARA: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveFileHistory()
        {
            try
            {
                var entry = new FileHistoryEntry
                {
                    FilePath = selectedFile,
                    FileName = Path.GetFileName(selectedFile),
                    ProcessedDate = DateTime.Now,
                    RecursiveCheck = checkBoxRParam.IsChecked ?? false,
                    RevocationCheck = checkBoxSParam.IsChecked ?? false
                };

                for (int i = 0; i < tabControlResults.Items.Count - 1; i++) 
                {
                    var tab = tabControlResults.Items[i] as TabItem;
                    if (tab != null)
                    {
                        string tabName = tab.Header.ToString();
                        string content = GetTabText(i);
                        entry.TabContents[tabName] = content;
                    }
                }

                System.Diagnostics.Debug.WriteLine($"SaveFileHistory: Сохраняем настройки для файла {entry.FileName}. Индивидуальные настройки: {AppSettings.Instance.EnableIndividualHistorySettings}");
                System.Diagnostics.Debug.WriteLine($"SaveFileHistory: Текущих алармов в MainWindow: {AlarmSettings.Count}");
                System.Diagnostics.Debug.WriteLine($"SaveFileHistory: Текущих YARA правил в MainWindow: {YaraRules.Count}");
                
                entry.AppliedAlarmSettings = new List<AlarmSetting>();
                foreach (var alarm in AlarmSettings)
                {
                    var newAlarm = new AlarmSetting
                    {
                        Enabled = alarm.Enabled,
                        Parameter = alarm.Parameter,
                        Condition = alarm.Condition,
                        Value = alarm.Value,
                        Tab = alarm.Tab,
                        Description = alarm.Description
                    };
                    entry.AppliedAlarmSettings.Add(newAlarm);
                }
                
                entry.AppliedYaraRules = new List<YaraRule>();
                foreach (var rule in YaraRules)
                {
                    entry.AppliedYaraRules.Add(new YaraRule
                    {
                        Enabled = rule.Enabled,
                        RulePath = rule.RulePath,
                        Description = rule.Description
                    });
                }
                
                System.Diagnostics.Debug.WriteLine($"SaveFileHistory: Сохранено в историю {entry.AppliedAlarmSettings.Count} алармов и {entry.AppliedYaraRules.Count} YARA правил");

                entry.YaraScanResults = GetTabText(7);
                entry.EntropyValue = GetTabText(6);
                entry.VirusTotalResults = GetTabText(5);
                
                int visualAlarmCount = 0;
                for (int i = 0; i < tabControlResults.Items.Count - 1; i++) 
                {
                    var tab = tabControlResults.Items[i] as TabItem;
                    if (tab != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"SaveFileHistory: Проверяем вкладку '{tab.Header}', Tag = {tab.Tag}");
                        if (tab.Tag is bool tagValue && tagValue == true)
                        {
                            visualAlarmCount++;
                        }
                    }
                }
                entry.AlarmCount = visualAlarmCount;

                FileHistory.Instance.AddEntry(entry);
                
                System.Diagnostics.Debug.WriteLine($"SaveFileHistory: История сохранена для файла {entry.FileName}. " +
                    $"Алармов: {entry.AppliedAlarmSettings.Count}, YARA правил: {entry.AppliedYaraRules.Count}, " +
                    $"Локальные настройки: {AppSettings.Instance.EnableIndividualHistorySettings}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при сохранении истории: {ex.Message}");
            }
        }

        private void LoadFileHistory()
        {
            try
            {
                var entries = FileHistory.Instance.Entries;
                if (entries.Count == 0)
                {
                    SetTabText(11, "История пуста. Файлы появятся здесь после их обработки.");
                    return;
                }

                if (historyRichTextBox == null) return;

                historyRichTextBox.Document.Blocks.Clear();

                Paragraph headerParagraph = new Paragraph();
                headerParagraph.Inlines.Add(new Run("=== ИСТОРИЯ ОБРАБОТКИ ФАЙЛОВ ===\n"));
                historyRichTextBox.Document.Blocks.Add(headerParagraph);

                Paragraph hintParagraph = new Paragraph();
                hintParagraph.Inlines.Add(new Run("💡 Подсказка: Кликните на название файла для просмотра детальной информации\n"));
                historyRichTextBox.Document.Blocks.Add(hintParagraph);


                var sortedEntries = entries.OrderByDescending(e => e.ProcessedDate).ToList();

                for (int i = 0; i < sortedEntries.Count; i++)
                {
                    var entry = sortedEntries[i];
                    Paragraph p = new Paragraph();
                    p.Margin = new Thickness(0, 5, 0, 0);

                    Hyperlink fileLink = new Hyperlink();
                    fileLink.Inlines.Add(new Run($"📁 {entry.FileName}"));
                    fileLink.Tag = entry;
                    fileLink.Click += FileLink_Click;
                    fileLink.Foreground = Brushes.Blue;
                    fileLink.TextDecorations = TextDecorations.Underline;
                    
                    p.Inlines.Add(fileLink);
                    p.Inlines.Add(new Run($"\n📅 {entry.ProcessedDate:dd.MM.yyyy HH:mm:ss}"));
                    


                    if (AppSettings.Instance.EnableIndividualHistorySettings)
                    {
                        p.Inlines.Add(new Run($"\n🔧 Локальные настройки:{entry.AppliedYaraRules.Count} YARA"));
                    }
                    else
                    {
                        p.Inlines.Add(new Run($"\n🔧 Общие настройки:{entry.AppliedYaraRules.Count} YARA"));
                    }

                    p.Inlines.Add(new Run("\n"));
                    Hyperlink restoreLink = new Hyperlink();
                    restoreLink.Inlines.Add(new Run("🔄 Восстановить"));
                    restoreLink.Tag = entry;
                    restoreLink.Click += RestoreLink_Click;
                    restoreLink.Foreground = Brushes.Green;
                    restoreLink.TextDecorations = TextDecorations.Underline;
                    p.Inlines.Add(restoreLink);

                    p.Inlines.Add(new Run("\n" + new string('-', 80) + "\n\n"));

                    historyRichTextBox.Document.Blocks.Add(p);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при загрузке истории: {ex.Message}");
                if (historyRichTextBox != null)
                {
                    historyRichTextBox.Document.Blocks.Clear();
                    historyRichTextBox.AppendText("Ошибка при загрузке истории файлов.");
                }
            }
        }

        private void FileLink_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Hyperlink link && link.Tag is FileHistoryEntry entry)
                {
                    OpenFileDetailsTab(entry);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при открытии деталей файла: {ex.Message}", 
                               "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RestoreLink_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Hyperlink link && link.Tag is FileHistoryEntry entry)
                {
                    RestoreFileFromHistory(entry);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при восстановлении файла: {ex.Message}", 
                               "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OpenFileDetailsTab(FileHistoryEntry entry)
        {
            try
            {
                string tabName = $"История: {entry.FileName}";
                
                for (int i = 0; i < tabControlResults.Items.Count; i++)
                {
                    var tab = tabControlResults.Items[i] as TabItem;
                    if (tab != null && tab.Header.ToString() == tabName)
                    {
                        tabControlResults.SelectedIndex = i;
                        return;
                    }
                }

                TabItem newTab = new TabItem { Header = tabName };
                RichTextBox rtb = new RichTextBox
                {
                    IsDocumentEnabled = true,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    VerticalAlignment = VerticalAlignment.Stretch,
                    Margin = new Thickness(5),
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    IsReadOnly = true
                };

                newTab.Content = rtb;
                tabControlResults.Items.Add(newTab);
                tabControlResults.SelectedIndex = tabControlResults.Items.Count - 1;
                PopulateFileDetailsTab(rtb, entry);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при создании вкладки деталей: {ex.Message}", 
                               "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void PopulateFileDetailsTab(RichTextBox rtb, FileHistoryEntry entry)
        {
            try
            {
                rtb.Document.Blocks.Clear();

                Paragraph headerParagraph = new Paragraph();
                headerParagraph.Inlines.Add(new Run($"=== ДЕТАЛЬНАЯ ИНФОРМАЦИЯ О ФАЙЛЕ ===\n"));
                headerParagraph.Inlines.Add(new Run($"📁 Файл: {entry.FileName}\n"));
                headerParagraph.Inlines.Add(new Run($"📍 Путь: {entry.FilePath}\n"));
                headerParagraph.Inlines.Add(new Run($"📅 Дата обработки: {entry.ProcessedDate:dd.MM.yyyy HH:mm:ss}\n"));
                headerParagraph.Inlines.Add(new Run($"⚙️ Рекурсивная проверка: {(entry.RecursiveCheck ? "Да" : "Нет")}\n"));
                headerParagraph.Inlines.Add(new Run($"🔍 Проверка отзыва: {(entry.RevocationCheck ? "Да" : "Нет")}\n"));
                headerParagraph.Inlines.Add(new Run($"⚠️ Количество алармов: {entry.AlarmCount}\n"));
                headerParagraph.Inlines.Add(new Run($"🔧 Применено алармов: {entry.AppliedAlarmSettings.Count}\n"));
                headerParagraph.Inlines.Add(new Run($"🛡️ Применено YARA правил: {entry.AppliedYaraRules.Count}\n"));
                headerParagraph.Inlines.Add(new Run(new string('=', 20) + "\n"));
                rtb.Document.Blocks.Add(headerParagraph);

                foreach (var tabContent in entry.TabContents)
                {
                    Paragraph sectionParagraph = new Paragraph();
                    sectionParagraph.Inlines.Add(new Run($"=== {tabContent.Key} ===\n"));
                    rtb.Document.Blocks.Add(sectionParagraph);

                    Paragraph contentParagraph = new Paragraph();
                    AppendFormattedTextWithAlarms(contentParagraph, tabContent.Value);
                    rtb.Document.Blocks.Add(contentParagraph);
                }


               
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при заполнении вкладки деталей: {ex.Message}");
                rtb.Document.Blocks.Clear();
                rtb.AppendText($"Ошибка при загрузке деталей файла: {ex.Message}");
            }
        }

        private void AppendFormattedTextWithAlarms(Paragraph paragraph, string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                paragraph.Inlines.Add(new Run("(пусто)\n"));
                return;
            }

            string alarmTag = "(!ALARM!)";
            int lastIndex = 0;
            int alarmIndex = text.IndexOf(alarmTag, lastIndex);

            while (alarmIndex != -1)
            {
                if (alarmIndex > lastIndex)
                {
                    paragraph.Inlines.Add(new Run(text.Substring(lastIndex, alarmIndex - lastIndex)));
                }

                Run alarmRun = new Run(alarmTag);
                alarmRun.Foreground = Brushes.Red;
                alarmRun.FontWeight = FontWeights.Bold;
                paragraph.Inlines.Add(alarmRun);

                lastIndex = alarmIndex + alarmTag.Length;
                alarmIndex = text.IndexOf(alarmTag, lastIndex);
            }

            if (lastIndex < text.Length)
            {
                paragraph.Inlines.Add(new Run(text.Substring(lastIndex)));
            }
        }

        private void RestoreFileFromHistory(FileHistoryEntry entry)
        {
            try
            {
                if (!File.Exists(entry.FilePath))
                {
                    MessageBox.Show($"Файл {entry.FileName} не найден по пути:\n{entry.FilePath}", 
                                   "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _isRestoringHistory = true;
                

                SetSelectedFile(entry.FilePath);


                checkBoxRParam.IsChecked = entry.RecursiveCheck;
                checkBoxSParam.IsChecked = entry.RevocationCheck;


                for (int i = 0; i < tabControlResults.Items.Count - 1; i++)
                {
                    var tab = tabControlResults.Items[i] as TabItem;
                    if (tab != null && entry.TabContents.ContainsKey(tab.Header.ToString()))
                    {
                        SetTabText(i, entry.TabContents[tab.Header.ToString()]);
                    }
                }


                ApplyAlarmSettings(); 

                _isRestoringHistory = false;


                string settingsInfo;
                if (AppSettings.Instance.EnableIndividualHistorySettings)
                {
                    settingsInfo = $"• Применены индивидуальные настройки файла ({YaraRules.Count} YARA правил)";
                }
                else
                {
                    settingsInfo = "• Применены общие настройки приложения";
                }

                MessageBox.Show($"История для файла {entry.FileName} успешно восстановлена!\n\nВосстановлены:\n• Содержимое всех вкладок\n• Настройки проверки на момент обработки\n{settingsInfo}", 
                               "Восстановление", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _isRestoringHistory = false;
                MessageBox.Show($"Ошибка при восстановлении истории: {ex.Message}", 
                               "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearHistory()
        {
            var result = MessageBox.Show("Вы уверены, что хотите очистить всю историю файлов?\n\nЭто действие нельзя отменить.", 
                                        "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Question);
            
            if (result == MessageBoxResult.Yes)
            {
                FileHistory.Instance.ClearHistory();
                LoadFileHistory();
                MessageBox.Show("История файлов успешно очищена.", "Очистка", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ButtonClearHistory_Click(object sender, RoutedEventArgs e)
        {
            ClearHistory();
        }

        public void UpdateSettingsBasedOnIndividualHistorySetting()
        {
            try
            {
                if (string.IsNullOrEmpty(selectedFile)) return;
                

                string currentFile = selectedFile;
                selectedFile = null;
                SetSelectedFile(currentFile);
                
                System.Diagnostics.Debug.WriteLine($"UpdateSettingsBasedOnIndividualHistorySetting: Настройки обновлены для файла {Path.GetFileName(currentFile)}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка при обновлении настроек: {ex.Message}");
            }
        }

        public void UpdateFileHistoryEntrySettings(FileHistoryEntry entry, List<AlarmSetting> alarms, List<YaraRule> yaraRules)
        {
            if (entry == null) return;

            System.Diagnostics.Debug.WriteLine($"UpdateFileHistoryEntrySettings: Обновление настроек для записи в истории файла {entry.FileName}");
            System.Diagnostics.Debug.WriteLine($"UpdateFileHistoryEntrySettings: Входящие алармы: {alarms.Count}, входящие YARA: {yaraRules.Count}");
            
            entry.AppliedAlarmSettings = new List<AlarmSetting>(alarms);
            entry.AppliedYaraRules = new List<YaraRule>(yaraRules);
            FileHistory.Instance.SaveHistory();
            
            System.Diagnostics.Debug.WriteLine($"UpdateFileHistoryEntrySettings: Настройки для файла {entry.FileName} обновлены в истории. Алармов: {entry.AppliedAlarmSettings.Count}, YARA: {entry.AppliedYaraRules.Count}");
        }

        private List<YaraRule> GetDefaultYaraRules()
        {
            return new List<YaraRule>();
        }

        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
            e.Handled = true;
        }

        private async Task<string> ValidateYaraRulesSyntaxAsync(IProgress<int> progress)
        {
            int total = YaraRules.Count;
            int current = 0;
            foreach (var rule in YaraRules)
            {
                current++;
                progress?.Report((int)((double)current / total * 100));
                await Task.Yield();
            }
            return "Проверка завершена!";
        }

        public class YaraRuleNode
        {
            public string Name { get; set; }
            public string RuleText { get; set; }
            public string Error { get; set; }
            public List<YaraRuleNode> Children { get; set; } = new List<YaraRuleNode>();
            public override string ToString() => Name;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            InitYaraTree();
            listYaraRules.ItemsSource = YaraRules.Select(r => r.Name).ToList();
        }

        private void InitYaraTree()
        {
            var root1 = new YaraRuleNode { Name = "crypto_signature" };
            root1.Children.Add(new YaraRuleNode {
                Name = "Big_Numbers5",
                RuleText = "rule Big_Numbers5 {\n    meta: ... }",
                Error = null
            });
            root1.Children.Add(new YaraRuleNode {
                Name = "CRC32_poly_Constant",
                RuleText = "rule CRC32_poly_Constant {\n    meta: ... }",
                Error = "Ошибка синтаксиса: ..."
            });
            var yaraGroups = new List<YaraRuleNode> { root1 };
        }

        private void listYaraRules_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (listYaraRules.SelectedIndex >= 0 && listYaraRules.SelectedIndex < YaraRules.Count)
            {
                var rule = YaraRules[listYaraRules.SelectedIndex];
                textYaraRuleContent.Text = rule.RawText ?? rule.ToString();
                if (!string.IsNullOrWhiteSpace(rule.Error))
                {
                    textYaraRuleError.Text = rule.Error;
                    textYaraRuleError.Visibility = Visibility.Visible;
                }
                else
                {
                    textYaraRuleError.Text = string.Empty;
                    textYaraRuleError.Visibility = Visibility.Collapsed;
                }
                if (ruleWasMatched(rule))
                {
                    textYaraRuleContent.Background = Brushes.Red;
                    textYaraRuleContent.Foreground = Brushes.White;
                }
                else
                {
                    textYaraRuleContent.Background = Brushes.White;
                    textYaraRuleContent.Foreground = Brushes.Black;
                }
            }
            else
            {
                textYaraRuleContent.Text = string.Empty;
                textYaraRuleError.Text = string.Empty;
                textYaraRuleError.Visibility = Visibility.Collapsed;
                textYaraRuleContent.Background = Brushes.White;
                textYaraRuleContent.Foreground = Brushes.Black;
            }
        }

        private bool ruleWasMatched(YaraRule rule)
        {
            return rule.Matched;
        }
    }
}



 