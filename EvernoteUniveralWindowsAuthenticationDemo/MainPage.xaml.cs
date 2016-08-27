using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Evernote.EDAM.NoteStore;
using Thrift.Protocol;
using Thrift.Transport;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace EvernoteUniveralWindowsAuthenticationDemo
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

    private async void Button_Click(object sender, RoutedEventArgs e) {
      var result = await EvernoteAuthenticator.AuthenticateAsync(Host.Text, Key.Text, Secret.Text, Callback.Text);
      TTransport noteStoreTransport = new THttpClient(new Uri(result.EdamNoteStoreUrl));
      TProtocol noteStoreProtocol = new TBinaryProtocol(noteStoreTransport);
      var noteStore = new NoteStore.Client(noteStoreProtocol);
      var defaultNotebook = await Task.Run(() => noteStore.getDefaultNotebook(result.AuthToken));
      Output.Text = $"Your default notebook is {defaultNotebook.Name}";
    }
  }
}
