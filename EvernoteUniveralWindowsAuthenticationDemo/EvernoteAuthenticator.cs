//*********************************************************
//
// Copyright (c) Damian Mehers. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
// IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
// PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************
using System;
using System.Diagnostics;
using System.Globalization;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Web.Http;

namespace EvernoteUniveralWindowsAuthenticationDemo {
  /// <summary>
  /// A class that can be used to authenticate to Evernote on Windows Universal.
  /// Based on the Twitter example found here:  https://github.com/Microsoft/Windows-universal-samples/blob/master/Samples/WebAuthenticationBroker
  /// </summary>
  public static class EvernoteAuthenticator {
    public class Result {
      public string OauthTokenSecret { get; set; }
      public string AuthToken { get; set; }
      public string EdamShard { get; set; }
      public string EdamUserId { get; set; }
      public string EdamExpires { get; set; }
      public string EdamNoteStoreUrl { get; set; }
      public string EdamWebApiUrlPrefix { get; set; }

      public override string ToString() {
        return $"{nameof(OauthTokenSecret)}: {OauthTokenSecret}, {nameof(AuthToken)}: {AuthToken}, {nameof(EdamShard)}: {EdamShard}, {nameof(EdamUserId)}: {EdamUserId}, {nameof(EdamExpires)}: {EdamExpires}, {nameof(EdamNoteStoreUrl)}: {EdamNoteStoreUrl}, {nameof(EdamWebApiUrlPrefix)}: {EdamWebApiUrlPrefix}";
      }
    }

    /// <summary>
    /// Authenticate to Evernote on Windows Universal
    /// </summary>
    /// <param name="host">The Evernote server to use.  Either https://www.evernote.com or https://sandbox.evernote.com </param>
    /// <param name="key">Your Evernote API key</param>
    /// <param name="secret">Your Evernote API secret</param>
    /// <param name="callbackUrl">The callback URL used when user authenticates.  https://example.com works</param>
    /// <returns></returns>
    public static async Task<Result> AuthenticateAsync(string host, string key, string secret, string callbackUrl) {
      var requestTokenUrl = host + "/oauth";
      var authorizeUrl = host + "/OAuth.action";
      var accessTokenUrl = host + "/oauth";

      var nonce = GetNonce();
      var timeStamp = GetTimeStamp();
      var sigBaseStringParams = "oauth_callback=" + Uri.EscapeDataString(callbackUrl);
      sigBaseStringParams += "&" + "oauth_consumer_key=" + key;
      sigBaseStringParams += "&" + "oauth_nonce=" + nonce;
      sigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
      sigBaseStringParams += "&" + "oauth_timestamp=" + timeStamp;
        sigBaseStringParams += "&" + "oauth_version=1.0";
      var sigBaseString = "GET&";
      sigBaseString += Uri.EscapeDataString(requestTokenUrl) + "&" + Uri.EscapeDataString(sigBaseStringParams);
      var signature = GetSignature(sigBaseString, secret);

      var url = requestTokenUrl + "?" + sigBaseStringParams + "&oauth_signature=" +
                Uri.EscapeDataString(signature);
      var httpClient = new HttpClient();
      var response = await httpClient.GetStringAsync(new Uri(url));

      string oauthToken = null;
      string oauthTokenSecret = null;
      var keyValPairs = response.Split('&');

      foreach (var pair in keyValPairs) {
        var splits = pair.Split('=');
        switch (splits[0]) {
          case "oauth_token":
            oauthToken = splits[1];
            break;
          case "oauth_token_secret":
            oauthTokenSecret = splits[1];
            break;
        }
      }

      var startUri = new Uri(authorizeUrl + "?oauth_token=" + oauthToken);
      var endUri = new Uri(callbackUrl);

      var webAuthenticationResult =
        await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri, endUri);
      if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success) {
        var responseData = webAuthenticationResult.ResponseData;

        responseData = responseData.Substring(responseData.IndexOf("oauth_token", StringComparison.Ordinal));
        string oauthVerifier = null;
        keyValPairs = responseData.Split('&');

        foreach (var pair in keyValPairs) {
          var splits = pair.Split('=');
          switch (splits[0]) {
            case "oauth_token":
              oauthToken = splits[1];
              break;
            case "oauth_verifier":
              oauthVerifier = splits[1];
              break;
          }
        }
        nonce = GetNonce();
        timeStamp = GetTimeStamp();

        sigBaseStringParams = "oauth_consumer_key=" + key;
        sigBaseStringParams += "&" + "oauth_nonce=" + nonce;
        sigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
        sigBaseStringParams += "&" + "oauth_timestamp=" + timeStamp;
        sigBaseStringParams += "&" + "oauth_token=" + Uri.EscapeDataString(oauthToken);
        sigBaseStringParams += "&" + "oauth_verifier=" + Uri.EscapeDataString(oauthVerifier);
        sigBaseStringParams += "&" + "oauth_version=1.0";
        sigBaseString = "GET&";
        sigBaseString += Uri.EscapeDataString(accessTokenUrl) + "&" + Uri.EscapeDataString(sigBaseStringParams);
        signature = GetSignature(sigBaseString, secret, oauthTokenSecret);

        url = accessTokenUrl + "?" + sigBaseStringParams + "&oauth_signature=" +
              Uri.EscapeDataString(signature);
        httpClient = new HttpClient();
        response = await httpClient.GetStringAsync(new Uri(url));

        keyValPairs = response.Split('&');
        var result = new Result();

        foreach (var pair in keyValPairs) {
          var splits = pair.Split('=');
          switch (splits[0]) {
            case "oauth_token":
              result.AuthToken = Uri.UnescapeDataString(splits[1]);
              break;
            case "oauth_token_secret":
              result.OauthTokenSecret = Uri.UnescapeDataString(splits[1]);
              break;
            case "edam_shard":
              result.EdamShard = Uri.UnescapeDataString(splits[1]);
              break;
            case "edam_userId":
              result.EdamUserId = Uri.UnescapeDataString(splits[1]);
              break;
            case "edam_expires":
              result.EdamExpires = Uri.UnescapeDataString(splits[1]);
              break;
            case "edam_noteStoreUrl":
              result.EdamNoteStoreUrl = Uri.UnescapeDataString(splits[1]);
              break;
            case "edam_webApiUrlPrefix":
              result.EdamWebApiUrlPrefix = Uri.UnescapeDataString(splits[1]);
              break;
          }
        }
        return result;
      }
      if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp) {
        Debug.WriteLine("HTTP Error returned by AuthenticateAsync() : " + webAuthenticationResult.ResponseErrorDetail);
      } else {
        Debug.WriteLine("Error returned by AuthenticateAsync() : " + webAuthenticationResult.ResponseStatus);
      }
      return null;
    }


    private static string GetNonce() {
      var rand = new Random();
      var nonce = rand.Next(1000000000);
      return nonce.ToString();
    }

    private static string GetTimeStamp() {
      var sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
      return Math.Round(sinceEpoch.TotalSeconds).ToString(CultureInfo.InvariantCulture);
    }

    private static string GetSignature(string sigBaseString, string consumerSecretKey, string oauthTokenSecret = "") {
      var keyMaterial =
        CryptographicBuffer.ConvertStringToBinary(
          Uri.EscapeDataString(consumerSecretKey) + "&" + Uri.EscapeDataString(oauthTokenSecret),
          BinaryStringEncoding.Utf8);
      var hmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
      var macKey = hmacSha1Provider.CreateKey(keyMaterial);
      var dataToBeSigned = CryptographicBuffer.ConvertStringToBinary(sigBaseString, BinaryStringEncoding.Utf8);
      var signatureBuffer = CryptographicEngine.Sign(macKey, dataToBeSigned);
      var signature = CryptographicBuffer.EncodeToBase64String(signatureBuffer);

      return signature;
    }
  }
}
