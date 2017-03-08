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

    readonly Func<int,IBinaryKeyCreator> keyCreatorFactory;

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

      var keyCreator = GetKeyCreator(input);
      var salt = GetSalt(input, keyCreator);
      var key = GetKey(input, keyCreator, salt);

      return CreateCredentials(input.IterationCount, salt, key);
    }

    /// <summary>
    /// Creates a credentials instance from the given information.
    /// </summary>
    /// <returns>The credentials.</returns>
    /// <param name="iterationCount">Iteration count.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="key">Key.</param>
    protected virtual IPBKDF2Credentials CreateCredentials(int iterationCount, byte[] salt, byte[] key)
    {
      return new PBKDF2Credentials
      {
        IterationCount = iterationCount,
        SaltBytes = salt,
        KeyBytes = key,
      };
    }

    /// <summary>
    /// Gets the credentials verifier.
    /// </summary>
    /// <returns>A key creator service.</returns>
    /// <param name="input">Input.</param>
    IBinaryKeyCreator GetKeyCreator(IPBKDF2CredentialsInfo input)
    {
      return keyCreatorFactory(input.IterationCount);
    }

    /// <summary>
    /// Gets the salt from the creator service using the specified salt length.
    /// </summary>
    /// <returns>The salt.</returns>
    /// <param name="input">Input.</param>
    /// <param name="keyCreator">Key creator service.</param>
    byte[] GetSalt(IPBKDF2CredentialsInfo input, IBinaryKeyCreator keyCreator)
    {
      return keyCreator.CreateRandomSalt(input.SaltLength);
    }

    /// <summary>
    /// Gets the key from the creator service using the specified password and salt.
    /// </summary>
    /// <returns>The key.</returns>
    /// <param name="input">Input.</param>
    /// <param name="keyCreator">Key creator service.</param>
    /// <param name="salt">Salt.</param>
    byte[] GetKey(IPBKDF2CredentialsInfo input, IBinaryKeyCreator keyCreator, byte[] salt)
    {
      return keyCreator.CreateKey(input.GetPasswordAsByteArray(), salt, input.KeyLength);
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
    /// <param name="keyCreatorFactory">A delegate factory which creates instances of the key creator service.</param>
    public PBKDF2CredentialsFactory(Func<int,IBinaryKeyCreator> keyCreatorFactory)
    {
      if(keyCreatorFactory == null)
        throw new ArgumentNullException(nameof(keyCreatorFactory));

      this.keyCreatorFactory = keyCreatorFactory;
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
