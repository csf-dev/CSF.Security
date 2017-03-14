//
// IAuthenticationRequest.cs
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
  /// Represents a request (which passes through an instance of <see cref="IPasswordAuthenticationService"/>,
  /// bringing together the information pertaining to an authentication attempt in a single context type.
  /// </summary>
  public interface IPasswordAuthenticationRequest
  {
    /// <summary>
    /// Gets or sets the entered credentials.
    /// </summary>
    /// <value>The entered credentials.</value>
    IPassword EnteredCredentials { get; set; }

    /// <summary>
    /// Gets or sets the stored credentials from a data-store.
    /// </summary>
    /// <value>The stored credentials.</value>
    IStoredCredentials StoredCredentials { get; set; }

    /// <summary>
    /// Gets or sets the credentials object (after deserialization).
    /// </summary>
    /// <value>The credentials object.</value>
    object CredentialsObject { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the password has been verified.
    /// </summary>
    /// <value><c>true</c> if the password is verified; otherwise, <c>false</c>.</value>
    bool PasswordVerified { get; set; }

    /// <summary>
    /// Gets or sets the overall result.
    /// </summary>
    /// <value>The result.</value>
    IAuthenticationResult Result { get; set; }

    /// <summary>
    /// Gets or sets the password verifier service to use.
    /// </summary>
    /// <value>The verifier.</value>
    IPasswordVerifier Verifier { get; set; }
  }
}
