//
// IPBKDF2Credentials.cs
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
  /// Represents a specialisation of <see cref="IStoredCredentialsWithKeyAndSalt"/> that also contains a PBKDF2
  /// iteration count.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Passing an instance which implements this interface to the constructor of a
  /// <see cref="T:PBKDF2CredentialVerifier{TEnteredCredentials,TStoredCredentials}"/> (as the stored credentials)
  /// allows it to configure its own iteration count from the stored credentials.
  /// </para>
  /// </remarks>
  public interface IPBKDF2Credentials : IStoredCredentialsWithKeyAndSalt
  {
    /// <summary>
    /// Gets the iteration count.
    /// </summary>
    /// <value>The iteration count.</value>
    int IterationCount { get; }
  }
}
