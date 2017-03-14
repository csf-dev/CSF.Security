//
// PBKDF2CredentialVerifier.cs
//
// Author:
//       Craig Fowler <craig@craigfowler.me.uk>
//
// Copyright (c) 2016 Craig Fowler
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
using System.Security.Cryptography;
using System.Linq;

namespace CSF.Security.Authentication
{
  /// <summary>
  /// Implementation of an <see cref="IPasswordVerifier"/> which uses the PBKDF2 mechanism.
  /// </summary>
  public class PBKDF2PasswordVerifier : IPasswordVerifier, ICredentialsCreator
  {
    #region constants

    static readonly RNGCryptoServiceProvider _randomNumberGenerator;
    internal const int DefaultIterationCount = 256000, DefaultKeyLength = 16, DefaultSaltLength = 16;

    #endregion

    #region fields

    private int iterationCount, saltLength, keyLength;

    #endregion

    #region properties

    /// <summary>
    /// Gets the iteration count for the PBKDF2 operations.
    /// </summary>
    /// <value>The iteration count.</value>
    protected int IterationCount
    {
      get {
        return iterationCount;
      }
    }

    /// <summary>
    /// Gets the secure random number generator.
    /// </summary>
    /// <value>The random number generator.</value>
    protected RNGCryptoServiceProvider RandomNumberGenerator
    {
      get {
        return _randomNumberGenerator;
      }
    }

    #endregion

    #region methods

    /// <summary>
    /// Verifies that the entered credentials match the stored credentials.
    /// </summary>
    /// <param name="enteredCredentials">Entered credentials.</param>
    /// <param name="credentialsObject">Stored credentials.</param>
    public virtual bool Verify(IEnteredPassword enteredCredentials, object credentialsObject)
    {
      if(enteredCredentials == null)
      {
        throw new ArgumentNullException(nameof(enteredCredentials));
      }
      if(credentialsObject == null)
      {
        throw new ArgumentNullException(nameof(credentialsObject));
      }

      var pbkdf2Credentials = (IPBKDF2Credentials) credentialsObject;

      var storedSalt = pbkdf2Credentials.GetSaltAsByteArray();
      var storedKey = pbkdf2Credentials.GetKeyAsByteArray();
      var enteredPassword = enteredCredentials.GetPasswordAsByteArray();

      var generatedKey = CreateKey(enteredPassword, storedSalt, storedKey.Length);
      return Enumerable.SequenceEqual(generatedKey, storedKey);
    }


    public virtual object CreateCredentials(IEnteredPassword password)
    {
      if(password == null)
      {
        return null;
      }

      var salt = CreateRandomSalt();
      var key = CreateKey(password.GetPasswordAsByteArray(), salt, keyLength);

      return new PBKDF2Credentials
      {
        IterationCount = iterationCount,
        Key = Convert.ToBase64String(key),
        Salt = Convert.ToBase64String(salt)
      };
    }

    /// <summary>
    /// Creates a random salt, as a byte array.
    /// </summary>
    /// <returns>The random salt.</returns>
    protected virtual byte[] CreateRandomSalt()
    {
      var output = new byte[saltLength];

      RandomNumberGenerator.GetBytes(output);

      return output;
    }

    /// <summary>
    /// Creates a key for a given password and salt, of a desired key length.
    /// </summary>
    /// <returns>The generated key.</returns>
    /// <param name="password">The password.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="length">The key length.</param>
    public virtual byte[] CreateKey(byte[] password, byte[] salt, int length)
    {
      if(password == null)
      {
        throw new ArgumentNullException(nameof(password));
      }
      if(salt == null)
      {
        throw new ArgumentNullException(nameof(salt));
      }
      if(length < 1)
      {
        throw new ArgumentOutOfRangeException(nameof(length), "Key length must be more than zero.");
      }

      var utility = GetHashingUtility(password, salt);
      return utility.GetBytes(length);
    }

    /// <summary>
    /// Gets the instance of <c>Rfc2898DeriveBytes</c>.
    /// </summary>
    /// <returns>The hashing utility.</returns>
    /// <param name="password">Password.</param>
    /// <param name="salt">Salt.</param>
    protected virtual Rfc2898DeriveBytes GetHashingUtility(byte[] password, byte[] salt)
    {
      return new Rfc2898DeriveBytes(password, salt, IterationCount);
    }

#pragma warning disable RECS0082 // Parameter has the same name as a member and hides it
    private void ConfigureInitialisationParameters(int iterationCount = DefaultIterationCount,
                                                   int keyLength = DefaultKeyLength,
                                                   int saltLength = DefaultSaltLength)
#pragma warning restore RECS0082 // Parameter has the same name as a member and hides it
    {
      if(iterationCount < 1)
      {
        throw new ArgumentOutOfRangeException(nameof(iterationCount), "Iteration count must be more than zero.");
      }
      if(saltLength < 8)
      {
        throw new ArgumentOutOfRangeException(nameof(saltLength), "The salt must be at least 8 bytes in length.");
      }
      if(keyLength < 1)
      {
        throw new ArgumentOutOfRangeException(nameof(keyLength), "The key must be at least 1 byte in length.");
      }

      this.iterationCount = iterationCount;
      this.saltLength = saltLength;
      this.keyLength = keyLength;
    }

    #endregion

    #region constructors

    /// <summary>
    /// Initializes a new instance of the <see cref="PBKDF2PasswordVerifier"/> class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The iteration count is the "work factor" indicating how difficult it is to perform the hashing operation.
    /// As of 2012, a sane starting point I have seen suggests 64000 iterations.  This should double roughly every
    /// two years (thus 256k as of 2016).
    /// </para>
    /// <para>
    /// This however is only really a starting point.  It is important to measure the performance on your own hardware
    /// and also consider performance on a "password cracking machine" (loaded with GPUs and the like).  You are aiming
    /// for it to take as long as is acceptable on your own hardware (10ms or so for a multi-user network/web service
    /// seems reasonable) and also to take a long as possible on the reference "cracking machine".
    /// </para>
    /// <para>
    /// The aim is to ensure that you have acceptable performance for logins on your own hardware, but that crackers
    /// wouldn't be able to try thousands/millions of passwords every second if they compromised your database.
    /// </para>
    /// </remarks>
    /// <param name="iterationCount">Iteration count.</param>
    /// <param name="keyLength">Key byte length.</param>
    /// <param name="saltLength">Salt byte length.</param>
    public PBKDF2PasswordVerifier(int iterationCount = DefaultIterationCount,
                                  int keyLength = DefaultKeyLength,
                                  int saltLength = DefaultSaltLength)
    {
      ConfigureInitialisationParameters(iterationCount, keyLength, saltLength);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PBKDF2PasswordVerifier"/> class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This overload of the constructor initialises the instance from the parameters object.
    /// </para>
    /// </remarks>
    /// <param name="parameters">The parameters object.</param>
    public PBKDF2PasswordVerifier(IPBKDF2Parameters parameters)
    {
      if(parameters != null)
      {
        ConfigureInitialisationParameters(parameters.GetIterationCount(),
                                          parameters.GetKeyLength(),
                                          parameters.GetSaltLength());
      }
      else
      {
        ConfigureInitialisationParameters();
      }
    }

    /// <summary>
    /// Initializes the <see cref="PBKDF2PasswordVerifier"/> class.
    /// </summary>
    static PBKDF2PasswordVerifier()
    {
      _randomNumberGenerator = new RNGCryptoServiceProvider();
    }

    #endregion
  }
}

