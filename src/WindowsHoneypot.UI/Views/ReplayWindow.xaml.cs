using System.Globalization;
using System.Windows;
using System.Windows.Data;
using WindowsHoneypot.UI.ViewModels;

namespace WindowsHoneypot.UI.Views;

/// <summary>
/// Interaction logic for ReplayWindow.xaml
/// Implements Requirements 13.6, 13.7, 13.8: Timeline visualization, PDF export, non-technical UI
/// </summary>
public partial class ReplayWindow : Window
{
    public ReplayWindow(ReplayViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}

/// <summary>
/// Converter for position to percentage display
/// </summary>
public class PositionToPercentageConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values.Length == 2 && values[0] is int current && values[1] is int total && total > 0)
        {
            var percentage = (double)current / total * 100;
            return $"{percentage:F1}%";
        }
        return "0%";
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
