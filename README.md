# EnUWPAuthDemo
A example of authenticating to Evernote on Windows Universal

You'll want to copy the `EvernoteAuthenticator` class.

``` C#
      var result = await EvernoteAuthenticator.AuthenticateAsync(Host.Text, Key.Text, Secret.Text, Callback.Text);
      
      TTransport noteStoreTransport = new THttpClient(new Uri(result.EdamNoteStoreUrl));
      TProtocol noteStoreProtocol = new TBinaryProtocol(noteStoreTransport);
      var noteStore = new NoteStore.Client(noteStoreProtocol);
      var defaultNotebook = await Task.Run(() => noteStore.getDefaultNotebook(result.AuthToken));
      Output.Text = $"Your default notebook is {defaultNotebook.Name}";
```
