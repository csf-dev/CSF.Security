//
// PasswordAuthenticationRequest.cs
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
namespace CSF.Security.Authentication
{
  /// <summary>
  /// Implementation of <see cref="IPasswordAuthenticationRequest"/> which is generic for the entered &amp; stored
  /// credentials, as well as for the authentication result.
  /// </summary>
  public class PasswordAuthenticationRequest<TEntered, TStored, TResult> : IPasswordAuthenticationRequest
    where TEntered : IPassword
    where TStored : IStoredCredentials
    where TResult : IAuthenticationResult
  {
    #region properties

    /// <summary>
    /// Gets or sets the entered credentials.
    /// </summary>
    /// <value>The entered credentials.</value>
    public TEntered EnteredCredentials { get; set; }

    /// <summary>
    /// Gets or sets the stored credentials from a data-store.
    /// </summary>
    /// <value>The stored credentials.</value>
    public TStored StoredCredentials { get; set; }

    /// <summary>
    /// Gets or sets the credentials object (after deserialization).
    /// </summary>
    /// <value>The credentials object.</value>
    public object CredentialsObject { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the password has been verified.
    /// </summary>
    /// <value><c>true</c> if the password is verified; otherwise, <c>false</c>.</value>
    public bool PasswordVerified { get; set; }

    /// <summary>
    /// Gets or sets the overall result.
    /// </summary>
    /// <value>The result.</value>
    public TResult Result { get; set; }

    /// <summary>
    /// Gets or sets the password verifier service to use.
    /// </summary>
    /// <value>The verifier.</value>
    public IPasswordVerifier Verifier { get; set; }

    #endregion

    #region explicit interface implementation

    IPassword IPasswordAuthenticationRequest.EnteredCredentials
    {
      get { return EnteredCredentials; }
      set { EnteredCredentials = (TEntered) value; }
    }

    IStoredCredentials IPasswordAuthenticationRequest.StoredCredentials
    {
      get { return StoredCredentials; }
      set { StoredCredentials = (TStored) value; }
    }

    IAuthenticationResult IPasswordAuthenticationRequest.Result
    {
      get { return Result; }
      set { Result = (TResult) value; }
    }

    #endregion
  }
}
