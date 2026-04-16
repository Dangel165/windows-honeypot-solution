using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace WindowsHoneypot.UI.Controls;

/// <summary>
/// Reusable timeline control for displaying attack activities
/// Implements Requirement 13.4: Visualize activities in timeline format
/// </summary>
public partial class TimelineControl : UserControl
{
    public TimelineControl()
    {
        InitializeComponent();
    }
}

/// <summary>
/// Converter to show empty state when count is zero
/// </summary>
public class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int count)
        {
            return count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
