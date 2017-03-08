//
// PBKDF2CredentialsFactory.cs
//
// Author:
//       Craig Fowler <craig@csf-dev.com>
//
// Copyright (c) 2017 Craig Fowler
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
namespace CSF.Security
{
  /// <summary>
  /// Implementation of <see cref="ICredentialsFactory"/> which creates credentials suitable for the PBKDF2 verification
  /// mechanism.
  /// </summary>
  public class PBKDF2CredentialsFactory : ICredentialsFactory<IPBKDF2Credentials, IPBKDF2CredentialsInfo>
  {
    #region fields

    readonly Func<int,PBKDF2CredentialVerifier> verifierFactory;

    #endregion

    #region methods

    /// <summary>
    /// Gets the credentials from the given input.
    /// </summary>
    /// <returns>The credentials.</returns>
    /// <param name="input">Input.</param>
    public IPBKDF2Credentials GetCredentials(IPBKDF2CredentialsInfo input)
    {
      if(input == null)
      {
        throw new ArgumentNullException(nameof(input));
      }

      var verifier = GetVerifier(input);
      var salt = GetSalt(input, verifier);
      var key = GetKey(input, verifier, salt);

      return new PBKDF2Credentials
      {
        IterationCount = input.IterationCount,
        SaltBytes = salt,
        KeyBytes = key,
      };
    }

    /// <summary>
    /// Gets the credentials verifier.
    /// </summary>
    /// <returns>The verifier.</returns>
    /// <param name="input">Input.</param>
    PBKDF2CredentialVerifier GetVerifier(IPBKDF2CredentialsInfo input)
    {
      return verifierFactory(input.IterationCount);
    }

    /// <summary>
    /// Gets the salt from the verifier using the specified salt length.
    /// </summary>
    /// <returns>The salt.</returns>
    /// <param name="input">Input.</param>
    /// <param name="verifier">Verifier.</param>
    byte[] GetSalt(IPBKDF2CredentialsInfo input, PBKDF2CredentialVerifier verifier)
    {
      return verifier.CreateRandomSalt(input.SaltLength);
    }

    /// <summary>
    /// Gets the key from the verifier using the specified password and salt.
    /// </summary>
    /// <returns>The key.</returns>
    /// <param name="input">Input.</param>
    /// <param name="verifier">Verifier.</param>
    /// <param name="salt">Salt.</param>
    byte[] GetKey(IPBKDF2CredentialsInfo input, PBKDF2CredentialVerifier verifier, byte[] salt)
    {
      return verifier.CreateKey(input.GetPasswordAsByteArray(), salt, input.KeyLength);
    }

    object ICredentialsFactory.GetCredentials(object input)
    {
      return GetCredentials((IPBKDF2CredentialsInfo) input);
    }

    #endregion

    #region constructor

    /// <summary>
    /// Initializes a new instance of the <see cref="PBKDF2CredentialsFactory"/> class.
    /// </summary>
    /// <param name="verifierFactory">A delegate factory which creates instances of the verifier.</param>
    public PBKDF2CredentialsFactory(Func<int,PBKDF2CredentialVerifier> verifierFactory)
    {
      if(verifierFactory == null)
        throw new ArgumentNullException(nameof(verifierFactory));

      this.verifierFactory = verifierFactory;
    }

    #endregion

    #region contained type

    /// <summary>
    /// Simple contained type which holds credentials information.
    /// </summary>
    private class PBKDF2Credentials : IPBKDF2Credentials
    {
      public int IterationCount { get; set; }
      public byte[] KeyBytes { get; set; }
      public byte[] SaltBytes { get; set; }

      public byte[] GetKeyAsByteArray() => KeyBytes;

      public byte[] GetSaltAsByteArray() => SaltBytes;
    }

    #endregion
  }
}
