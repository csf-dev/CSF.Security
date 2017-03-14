//
// AuthenticationResult.cs
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
  /// Represents an authentication result.
  /// </summary>
  public class AuthenticationResult : IAuthenticationResult
  {
    /// <summary>
    /// Gets a value indicating whether the credentials (user account) were found.
    /// </summary>
    /// <value><c>true</c> if the credentials were found; otherwise, <c>false</c>.</value>
    public bool CredentialsFound { get; }

    /// <summary>
    /// Gets a value indicating whether this instance represents successful authentication.
    /// </summary>
    /// <value><c>true</c> if authentication was a success; otherwise, <c>false</c>.</value>
    public bool Success { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="T:CSF.Security.Authentication.AuthenticationResult"/> class.
    /// </summary>
    /// <param name="success">If set to <c>true</c> success.</param>
    /// <param name="credentialsFound">If set to <c>true</c> credentials found.</param>
    public AuthenticationResult(bool success, bool credentialsFound)
    {
      Success = success;
      CredentialsFound = credentialsFound;
    }
  }
}
