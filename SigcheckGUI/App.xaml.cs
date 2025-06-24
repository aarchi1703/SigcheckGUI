using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace SigcheckGUI
{
    ///<summary>
    ///</summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            try
            {
                base.OnStartup(e);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Исключение при запуске: {ex.Message}");
                try
                {
                    base.OnStartup(e);
                }
                catch
                {
                    MessageBox.Show($"Критическая ошибка при запуске приложения: {ex.Message}", "Ошибка", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Shutdown();
                }
            }
        }
    }
}
